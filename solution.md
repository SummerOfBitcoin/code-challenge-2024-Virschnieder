Mining a block, SoB assignment. 

My apporach :
1) **Took all tx with scriptpubkey_type p2pkh or p2wpkh.**
2) **I checked for double spending with every addition of new tx** (basically I kept a global set of txid to form an UTXO set and then I checked for collisions for every new tx).
3) **If the tx was free of double spending then I did ecdsa verification.**
    
For ecdsa verification we are required to have:
a. **message**
b. **public key**
c. **signature**

Calculation of message:
This involved calculation serealizated message hex of the tx data according to the scriptpubkey_type and then taking hash256 to get the final message. (There were lots of caveats and nouances I had to take care of while serealizing the tx data)

Calculation of public key:
This involved taking out data form witness field in case of p2wpkh type tx and scriptsig in case of p2pkh type tx.

Calculation of Signature:
This also involved taking out data form witness field in case of p2wpkh type tx and scriptsig in case of p2pkh type tx, but here we further breakdown this signature to get the r and s values. (signature are DER encoded)

4) **After getting the message, public key and r,s. I passed all these values into a ecdsa verifier function which can be found in the v.py file to verify the tx.** I wrote this function from scratch.

5) **If the tx is a valid one I calculated it's txid and wtxid and added it into a list of valid txid and wtxid**

6) **Calculation of witness commitment**
This involved calculation of merkle root using wtxid (take wtxid of coinbase as 0000000000000000000000000000000000000000000000000000000000000000). Then hashing it with witness root hash. The final hex is the witness commitment for the coinbase transaction. 

7) **Formation of seralized coinbase transaction:**
    coinbase = version + marker + flag + input_count+ input_c + vout + scriptsig_size + scriptsig + sequence + output_count + amount + scriptpubkey_size + scriptpubkey + amount_two + wtxid_commitment_size + wtxid_commitment + stack + size_stack + witness + locktime

8) **Calculation of coinbase txid and adding it as the first txid in the list of txid**

9) **Formation of block header** This invloved calculation of merkle root of txid and current time. 
block_header = version_bh + previous_block_hash + merkel_root + current_time + bits + nonce

10) **Now iterate over the values of nonce to get block header hash with difficulty less than the given difficulty of 0000ffff00000000000000000000000000000000000000000000000000000000**

11) **make an output.txt file as**
First line: The block header.
Second line: The serialized coinbase transaction.
Following lines: The transaction IDs (txids) of the transactions mined in the block, in order. The first txid should be that of the coinbase transaction
