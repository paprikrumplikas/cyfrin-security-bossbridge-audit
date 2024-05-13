# Vulnerabilities

1. Signature replay
2. Arbitrary from in transferFrom
3. Arbitrary messages
4. Gas bomb
5. MEV (practically present in all courses): qustion to ask: if someone sees my trx in the mempool, can they abuse the info they see to their benefit?
   1. Types:
      1. frontrunning
      2. sandwitch attacks
      3. (arbitrage)
      4. just in time liquidity (JIST)
   2. sources:
   3. how to prevent:
      1. change code logic and implement checks in appropriate functions
      2. use dark/private mempools, like flashbots protect, etc.
6. GOvernance attacks (in the Vault Gardians part, not here)
   


# Learnings

1. Use the audit checklist: https://github.com/Cyfrin/audit-checklist/tree/main

2. Assembly gives lower level access to the EVM. Not super low level, as there are abstractions in it. See [Yul upcodes](https://docs.soliditylang.org/en/v0.8.24/yul.html)
   1. In Solidity, in the EVM, whenever we do something we deploy contracts, variables, reading a lt of things, we need to loading in the memory first, and we need to be very specific about how much memory to load from/to.
   2. The audit checklist contains some elements regarding assembly use.
   3. To check what OPCODES we even need for a contract:
      1. Run the compiler `forge build`
      2. Check the output folder `out` --> TokenFactory.sol --> TokenFactory.json (Open, then F1, then type open in Json viewer) --> OPCODES

3. Openzeppelin contracts we see here for the first time: @note
   1. Pausable: allows ppl to add emergency stop
   2. ReentrancyGuard: allows to create a mutex locks on the codebase
   3. MessageHashUtils: helps us deal with signed data across multiple formats like EIP-712. Esentially helps format the ECDSA hashing into the EIP ways
   4. ECDSA: Elliptic Curve Dynamic Signature Algorithm operations: does the encryption

4. Private / public key demo: https://github.com/anders94/public-private-key-demo How to use: https://youtu.be/pUWmJ86X_do?t=67187

5. How classic public/private key cryptography works:
   1. msg + pirvate key => signed message
   2. signed message + PUBLIC key => can be confirmed (verified) signed
   We can do this in our smart contracts too, see [EIP-191 signed data standard](https://eips.ethereum.org/EIPS/eip-191)

6. How signing works:
   1. Take private key + message (data, function selector, parameters)
   2. Smash in into Elliptic Curve Digital Signature Algorithm
      1. This outputs v, r, and s
      2. we can use these values to verify someone's signature using ecrerecover

7. How verification works
   1. Get the signed message
      1. break it into v, r, and s
   2. Get the data itself
      1. Format it
   3. use it as input parameters for `ecrecover`


8. To inspect the functions in a contract, use `forge inspect L1BossBridge methods` @note 
   
9.  print slither output to file: `script -c "make slither" slither_output.txt` @note 

10. In testing, if we want to test event emission, we can use `vm.expcetEmit()`, but then we also need to actually emit the event we expect, and then the 2 will be compared: @note

      `vm.expectEmit(address(tokenBridge));`
     `emit Deposit(user, attacker, amountToDeposit);`

11. There is a variably type called `Account` in solidity. Like `Account account`. This comes with `account.key` and `account.addr`. @note

12. Foundry cheatcode: `vm.sign`


         // e MessageHashUtils.toEthSignedMessageHash(keccak256(message)) is used for putting the signed message in the correct format (EIPs),
        // because the signed message was just a raw lump of data combined
        // and then we call ECDSA.rocover to verify the signer.
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(keccak256(message)), v, r, s);



# Signatures

## Signatures vs. modifiers: @note
Modifiers and signatures both provide a form of authorization, but they operate differently and offer distinct advantages depending on the context and requirements of the application.

1. Signatures involve off-chain cryptographic signing of messages, which can then be verified on-chain.
2. They provide stronger cryptographic proof of authorization because they demonstrate that a specific entity has approved the transaction off-chain.
3. This signed message is transmitted to the contract and verified on-chain, ensuring that the transaction was approved by the entity possessing the private key corresponding to the signature.

## Signatures off-chain

Signatures enable off-chain signing by allowing a message to be signed using a private key off-chain and then verified on-chain using the corresponding public key. The process typically involves generating a message hash from the data to be signed, signing the hash with a private key using cryptographic algorithms like ECDSA (Elliptic Curve Digital Signature Algorithm), and then sending the signature along with the original message to be verified on-chain. This enables secure authorization of transactions or actions without the need to expose private keys on-chain, enhancing security and privacy.

## v, r, and s

In the context of cryptographic signatures, particularly with ECDSA (Elliptic Curve Digital Signature Algorithm), v, r, and s are components of the signature generated during the signing process.
These parameters are typically generated during the off-chain signing process.

 - v (Recovery ID): It is a value used to recover the public key from the signature. In Ethereum transactions, the value of v is typically either 27 or 28, with additional values used to indicate chain ID in Ethereum's EIP-155 to prevent replay attacks across different networks.
 - r (Signature Component): It represents part of the signature and is one of the two components generated during the signing process. It is used along with s to reconstruct the full signature.
 - s (Signature Component): It is the other component of the signature generated during the signing process. Together with r, it forms the complete signature.
  
When verifying a signature, these components are used along with the message hash and the signer's public key to verify the authenticity and integrity of the signed message. If the verification process succeeds, it confirms that the message was indeed signed by the entity possessing the corresponding private key.

@note The private key and the message hash are used as inputs to the digital signature algorithm to produce the signature components, typically denoted as r and s. The process involves complex mathematical operations on the elliptic curve, including the use of the private key to generate these components. This ensures that the signature is unique to both the message and the signer's private key.





