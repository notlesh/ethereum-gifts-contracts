pragma solidity ^0.4.17;

/**
 * The GiftRegistry contract is designed to store funds put up by a "giver" to
 * a "recipient" whose Ethereum address is not known or who may not have an
 * Ethereum account yet.
 * 
 * To accomplish this, we validate the recipient's claim against a 'signer'
 * address. This is defined in the contract as type 'address', and is indeed a
 * valid Ethereum address, but for our purposes it is simply a public/private
 * keypair used for signing and validating a claim request.
 * 
 * The idea is that giver creates an Ethereum account and publishes that to the
 * gift registry along with the gifted funds. He then gives the recipient
 * the private key. The recipient can then use the private key to validate himself
 * as the recipient, pointing the funds to any Ethereum address of his choosing.
 */
contract GiftRegistry {
    
    struct GiftEntry {
        address signer;
        uint balance;
    }
    
    mapping (address => GiftEntry) m_giftEntries;
    
    /**
     * Register a gift.
     * 
     * The things we care about in this call are:
     * 
     * 1) The amount of ETH being sent. This will be stored by the contract and
     *    eligible to be claimed by the recipient.
     * 2) The 'signer' address. This is an Ethereum address, but is not used to
     *    store or send any ETH. Rather, it is used to verify the recipient.
     */
    function registerGift(address signer) public payable {
        m_giftEntries[signer] = GiftEntry(signer, msg.value);
    }
    
    /**
     * Claim a registered gift.
     * 
     * The claim process involves verifying a couple different things:
     * 
     * 1) We independently derive a message containing the desired payout address
     *    (payee) as well as the desired payout amount, and compare its hash to
     *    the hash provided. [TODO: explain how this message is assembled]
     * 2) We verify that the signature is a product of the hash (e.g. that it has
     *    not been tampered with)
     * 3) We verify that the original 'signer' address is the signer of this
     *    message. Keep in mind that the 'signer' is not used to store or transfer
     *    any ETH, but rather to verify the recipient of the gift funds.
     */
    function claimGift(address signer, bytes signature, address payee, uint amount) public {
        
        GiftEntry storage giftEntry= m_giftEntries[signer];
        
        require(giftEntry.balance > 0); // will check both balance > 0 and "existence" of entry
        require(giftEntry.balance >= amount);
        
        // Note: sha3 a.k.a. keccak256 uses "tightly packing", client side must do the same to produce signature
        //       Also, client side prepends a static message before signing, need to do the same here.
        //       see: https://github.com/ethereum/go-ethereum/issues/3731
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 messageHash = keccak256(prefix, payee, amount);
        bool valid = verifySignature(messageHash, signature, signer);
        
        require(valid);
        
        giftEntry.balance -= amount;
        payee.transfer(amount); // on failure, will revert state
    }
    
    /**
     * Verify that 'signature' is a valid result of 'signer' signing 'message'.
     */
     function verifySignature(bytes32 messageHash, bytes signature, address signer) public pure returns (bool valid) {
         // TODO: implement
         //
         // Signing in a Solidity contract is confined to ecrecover, which uses
         // products of ECC (Eliptical Curve Cryptography), which is documented here:
         // https://web3js.readthedocs.io/en/1.0/web3-eth-personal.html#ecrecover
         // 
         // and explained here:
         // https://medium.com/hello-sugoi/ethereum-signing-and-validating-13a2d7cb0ee3
         //
         // It is assumed that the r, s, and v values are embedded in the signature.
         //
         // However, there are suggestions to simplify/abstract this. See:
         // https://github.com/ethereum/EIPs/issues/79
         // https://gist.github.com/axic/5b33912c6f61ae6fd96d6c4a47afde6d
         
         return true;
     }
     
}
