// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

/* 
* @title TokenFactory
* @dev Allows the owner to deploy new ERC20 contracts
* @dev This contract will be deployed on both an L1 & an L2
*/
contract TokenFactory is Ownable {
    mapping(string tokenSymbol => address tokenAddress) private s_tokenToAddress;

    event TokenDeployed(string symbol, address addr);

    constructor() Ownable(msg.sender) { }

    /*
     * @dev Deploys a new ERC20 contract
     * @param symbol The symbol of the new token
     * @param contractBytecode The bytecode of the new token
     */
    function deployToken(string memory symbol, bytes memory contractBytecode) public onlyOwner returns (address addr) {
        // q are you sure you want this out of scope? For one, it is memory, not even calldata, so it is not even that
        // gas efficient
        // q maybe this is a gas-efficient way to do this?
        assembly {
            // Yul opcodes: https://docs.soliditylang.org/en/v0.8.24/yul.html
            // This bit `add(contractBytecode, 0x20)` says the bytecode is X-Large
            // load bytecode
            // create a contract
            // @audit high: this wont work ony zksync! https://docs.zksync.io/build/support/faq.html#evm-compatibility
            addr := create(0, add(contractBytecode, 0x20), mload(contractBytecode))
        }
        s_tokenToAddress[symbol] = addr;
        emit TokenDeployed(symbol, addr);
    }

    // @audit info can be external
    function getTokenAddressFromSymbol(string memory symbol) public view returns (address addr) {
        return s_tokenToAddress[symbol];
    }
}
