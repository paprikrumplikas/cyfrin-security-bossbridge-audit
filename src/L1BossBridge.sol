// __| |_____________________________________________________| |__
// __   _____________________________________________________   __
//   | |                                                     | |
//   | | ____                  ____       _     _            | |
//   | || __ )  ___  ___ ___  | __ ) _ __(_) __| | __ _  ___ | |
//   | ||  _ \ / _ \/ __/ __| |  _ \| '__| |/ _` |/ _` |/ _ \| |
//   | || |_) | (_) \__ \__ \ | |_) | |  | | (_| | (_| |  __/| |
//   | ||____/ \___/|___/___/ |____/|_|  |_|\__,_|\__, |\___|| |
//   | |                                          |___/      | |
// __| |_____________________________________________________| |__
// __   _____________________________________________________   __
//   | |                                                     | |

// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import { L1Vault } from "./L1Vault.sol";

contract L1BossBridge is Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20; // e helps with weird ERC20s

    // @audit info: should be constant
    uint256 public DEPOSIT_LIMIT = 100_000 ether; // e cant deposit too many

    IERC20 public immutable token; // one bridge per token
    L1Vault public immutable vault; // one vault per token
    mapping(address account => bool isSigner) public signers; // e users who can "send" tokens from L1 to L2

    error L1BossBridge__DepositLimitReached();
    error L1BossBridge__Unauthorized();
    error L1BossBridge__CallFailed();

    event Deposit(address from, address to, uint256 amount);

    constructor(IERC20 _token) Ownable(msg.sender) {
        token = _token;
        vault = new L1Vault(token); // e launch a new vault
        // Allows the bridge to move tokens out of the vault to facilitate withdrawals
        vault.approveTo(address(this), type(uint256).max);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // q what happens when we disable an account mid-flight?
    function setSigner(address account, bool enabled) external onlyOwner {
        signers[account] = enabled;
    }

    /*
     * @notice Locks tokens in the vault and emits a Deposit event
     * the unlock event will trigger the L2 minting process. There are nodes listening
     * for this event and will mint the corresponding tokens on L2. This is a centralized process.
     * 
     * @param from The address of the user who is depositing tokens
     * @param l2Recipient The address of the user who will receive the tokens on L2
     * @param amount The amount of tokens to deposit
     */
    function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
        if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
            // e can be only 100_000 on the L2
            revert L1BossBridge__DepositLimitReached();
        }
        // @audit high:
        // 1. Alice approves token --> bridge.
        //    - she is about to send to trx to call depositTokensToL2
        // 3. Bob noitces 1), calls depositTokensToL2(from: Alice, l2Recipient: Bob, amount: all her money!)
        // @audit high: L1Vault::approveTo approves the bridge, so we can steal from the vault too!
        // and they can do this forever, so they can mint infinite amount of tokens for themselves on L2!
        // it is a combination of 2 issues,         vault.approveTo(address(this), type(uint256).max);
        token.safeTransferFrom(from, address(vault), amount);

        // Our off-chain service picks up this event and mints the corresponding tokens on L2
        // @audit info: should follow CEI (could be a low if we had more tokens which could have some weird callback
        // functionality)
        emit Deposit(from, l2Recipient, amount);
    }

    /*
     * @notice This is the function responsible for withdrawing tokens from L2 to L1.
     * Our L2 will have a similar mechanism for withdrawing tokens from L1 to L2.
     * @notice The signature is required to prevent replay attacks. 
     * 
     * @param to The address of the user who will receive the tokens on L1
     * @param amount The amount of tokens to withdraw
     * @param v The v value of the signature
     * @param r The r value of the signature
     * @param s The s value of the signature
     */
    // @audit high: signature replay attack! v, r, s ends up on the blockchain, and others can reuse this signature
    // how-to prevent: add nonce, deadline or some param in the function so the signed stuff can only be user once.
    // AND @note to prevent frontrunning, the first time it is signed it MUST to be signed by the actual signer, i.e.
    // msg.sender == signer

    // e this function has to be called by a trusted entity (singer), not the user
    // @note instead of using signatures, we could theoretically use a modifier that allows only trusted entities to
    // call this function.
    // However, signatures offer some benefits over modifiers, such as off-chain signing and stronger cryptographic
    // proof or authorization.
    // Based on this function, the signing is probably happening off-chain; v,r,s are tipically generated during
    // the off-chain signing process.

    function withdrawTokensToL1(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        sendToL1(
            v,
            r,
            s,
            abi.encode(
                address(token),
                0, // value
                abi.encodeCall(IERC20.transferFrom, (address(vault), to, amount))
            )
        );
    }

    /*
     * @notice This is the function responsible for withdrawing ETH from L2 to L1.
    @audit info this function is more general-purpose and can be used to execute arbitrary calls on L1, as indicated by
    its ability to take a message parameter that gets decoded into a contract call. This function is not limited to ETH
    withdrawals; the comment might not fully capture its versatility. 
     *
     * @param v The v value of the signature
     * @param r The r value of the signature
     * @param s The s value of the signature
     * @param message The message/data to be sent to L1 (can be blank)
     */
    // e @note this is being called by withdrawTokensToL1
    // q why not make this function internal?
    function sendToL1(uint8 v, bytes32 r, bytes32 s, bytes memory message) public nonReentrant whenNotPaused {
        // e MessageHashUtils.toEthSignedMessageHash(keccak256(message))  is used for putting the signed message in the
        // correct format (EIPs), because the signed message was just a raw lump of data combined
        // and then we call ECDSA.rocover to verify the signer.
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);

        if (!signers[signer]) {
            revert L1BossBridge__Unauthorized();
        }

        (address target, uint256 value, bytes memory data) = abi.decode(message, (address, uint256, bytes));

        // @follow-up slither says this is bad
        // @audit high No, this is not OK. They can send arbitrary messages
        // @audit since this is a low.level call, solidity has a hard time estimating how much gas this is gonna cost,
        // and a malicious user can send a data with crazy gas costs and essentially srcrew the signers, making calling
        // this function too costly for them
        (bool success,) = target.call{ value: value }(data);
        if (!success) {
            revert L1BossBridge__CallFailed();
        }
    }
}
