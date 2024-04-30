Mining a block, SoB assignment. 

My apporach :
-> Took all tx with scriptpubkey_type p2pkh or p2wpkh.
-> I checked for double spending with every addition of new tx.
-> If the tx was free of double spending then I did ecdsa verification.
    For ecdsa verification we are required to have:
    a. message
    b. public key
    c. signature

    Calculation of message:
    This involved calculation serealizated message hex of the tx data according to the scriptpubkey_type and then taking hash256 to get the final message. (There were lots of caveats and nouances I had to take care of while serealizing the tx data)

    Calculation of public key:
    