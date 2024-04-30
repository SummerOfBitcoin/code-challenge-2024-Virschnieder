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

5) **If the tx is a valid one I calculated it's txid and wtxid.**

6) **Calculation of witness commitment**
    This involved 
