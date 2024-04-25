
import json
import hashlib
import sys
import ecdsa
import os
import v
import time
original_stdout = sys.stdout

#function to convert integer to 4 bytes little endian then to hex and return the hex value
def int_to_hex(version):
    version = version.to_bytes(4, byteorder='little')
    version = version.hex()
    return version

def int_to_little_endian_8bytes(number):
    little_endian_bytes = number.to_bytes(8, byteorder='little')
    hex_representation = ''.join(format(byte, '02x') for byte in little_endian_bytes)
    return hex_representation

def int_to_little_endian_4bytes(number):
    little_endian_bytes = number.to_bytes(4, byteorder='little')
    hex_representation = ''.join(format(byte, '02x') for byte in little_endian_bytes)
    return hex_representation
#function to convert integert to compact size integer then to hex and return the hex value
def int_to_hex_compact_size_integer(value):
    if value < 253:
        return value.to_bytes(1, byteorder='little').hex()
    elif value < 65536:
        return (253).to_bytes(1, byteorder='little').hex() + value.to_bytes(2, byteorder='little').hex()
    elif value < 4294967296:
        return (254).to_bytes(1, byteorder='little').hex() + value.to_bytes(4, byteorder='little').hex()
    else:
        return (255).to_bytes(1, byteorder='little').hex() + value.to_bytes(8, byteorder='little').hex()
#reverse byte function then to hex and return the hex value
def reverse_byte(txid):
    txid = txid[::-1]
    return txid.hex()
#convert compact size integer to integer
def compact_size_integer_to_int(value):
    if value < 253:
        return value
    elif value == 253:
        return 2
    elif value == 254:
        return 4
    else:
        return 8
#convert 8bytes little endian to decimal
def little_endian_to_int(bytes_data):
    return int.from_bytes(bytes_data, byteorder='little')
    
# Path to the folder containing JSON files
folder_path = "./mempool"
counter = 0
temp = 0
temp_segwit = 0
count_valid_tx = 0
txid_set = set()
wtxid_set = set()
fee = 0
count_segwit_tx = 0
#This variable will store the concatenation of version, input_count, txids, vouts, scriptsig_size, scriptsig, sequence, output_count, value, scriptpubkey_size, lockingscript, locktime
with open('output.txt', 'w') as y:
    sys.stdout = y
    # Iterate over each file in the folder
    for filename in os.listdir(folder_path):
        # Check if the file is a JSON file
        if filename.endswith(".json"):
            # Construct the full path to the JSON file
            file_path = os.path.join(folder_path, filename)
            
            # Open the JSON file and load its contents
            with open(file_path, "r") as f:
                data = json.load(f)
            
            # Flag to track if all scriptpubkey_type are v0_p2pkh or v1_p2pkh   
            all_valid = True
            all_valid_segwit = True
            # Iterate over each vin in the file
            for vin in data.get("vin", []):
                scriptpubkey_type = vin.get("prevout", {}).get("scriptpubkey_type", "")
                
                # Check if scriptpubkey_type is neither v0_p2pkh nor v1_p2pkh
                if scriptpubkey_type not in ["v0_p2pkh", "v1_p2pkh", "p2pkh"]:
                    all_valid = False
                    break  # No need to check further if one is not valid
            
            for vin in data.get("vin", []):
                scriptpubkey_type = vin.get("prevout", {}).get("scriptpubkey_type", "")
                if scriptpubkey_type not in ["v0_p2wpkh"]:
                    all_valid_segwit = False
                    break
            if all_valid_segwit:
                count_segwit_tx += 1
                data_cs = ""
                array_m_segwit = []
                flag = 0
                data_wit = ""
                
                #Extract the data from the file
                version = data.get("version")
                locktime = data.get("locktime")
                txids = [vin.get("txid") for vin in data.get("vin", [])]
                vouts = [vin.get("vout") for vin in data.get("vin", [])]
                v_input = [vin.get("prevout", {}).get("value") for vin in data.get("vin", [])]
                sequence = [vin.get("sequence") for vin in data.get("vin", [])]
                value = [vout.get("value") for vout in data.get("vout", [])]
                scriptpubkey = [vout.get("scriptpubkey") for vout in data.get("vout", [])]
                scriptpubkey_utxo = [vin.get("prevout", {}).get("scriptpubkey") for vin in data.get("vin", [])]
                witness = [vin.get("witness") for vin in data.get("vin", [])]
                
                n_txids = len(txids)
                output_count = len(value)
                version_hex = int_to_hex(version)
                data_cs += version_hex
                data_wit += version_hex
                data_wit += "0001"
                array_m_segwit.append(version_hex)
                Input_count = int_to_hex_compact_size_integer(n_txids)
                data_cs += Input_count
                data_wit += Input_count

                hash_inps = ""
                hash_seq = ""

                for i in range(n_txids):
                    txids[i] = reverse_byte(bytes.fromhex(txids[i]))
                    data_cs += txids[i]
                    data_wit += txids[i]
                    hash_inps += txids[i]
                    vouts[i] = int_to_hex(vouts[i])
                    data_cs += vouts[i]
                    data_wit += vouts[i]
                    hash_inps += vouts[i]
                    data_cs += "00"
                    data_wit += "00"
                    sequence[i] = int_to_hex(sequence[i])
                    data_cs += sequence[i]
                    data_wit += sequence[i]
                    hash_seq += sequence[i]

                hash_seq = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_seq)).digest()).digest()
                hash_inps = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_inps)).digest()).digest()
                array_m_segwit.append(hash_inps.hex())
                array_m_segwit.append(hash_seq.hex())
                Output_count = int_to_hex_compact_size_integer(output_count)
                data_cs += Output_count
                data_wit += Output_count

                hash_out = ""

                for i in range(output_count):
                    value[i] = int_to_little_endian_8bytes(int(value[i]))
                    data_cs += value[i]
                    hash_out += value[i]
                    data_wit += value[i]
                    scriptpubkey_size = len(scriptpubkey[i])
                    scriptpubkey_size = scriptpubkey_size//2
                    scriptpubkey_size = int_to_hex_compact_size_integer(scriptpubkey_size)
                    data_cs += scriptpubkey_size
                    data_cs += scriptpubkey[i]
                    hash_out += scriptpubkey_size
                    hash_out += scriptpubkey[i]
                    data_wit += scriptpubkey_size
                    data_wit += scriptpubkey[i]     

                hash_out = hashlib.sha256(hashlib.sha256(bytes.fromhex(hash_out)).digest()).digest()
                array_m_segwit.append(hash_out.hex())
                locktime = int_to_hex(locktime)
                data_cs += locktime
                array_m_segwit.append(locktime)
                
                array_message = []
                for i in range(n_txids):
                    temp_a = array_m_segwit.copy()
                    temp_a.insert(3, txids[i])
                    temp_a.insert(4, vouts[i])
                    temp_a.insert(5, "1976a914")
                    # remove 0014 from the front of scriptpubkey_utxo
                    scriptpubkey_utxo[i] = scriptpubkey_utxo[i][4:]
                    temp_a.insert(6, scriptpubkey_utxo[i])
                    temp_a.insert(7, "88ac")
                    v_input[i] = int_to_little_endian_8bytes(v_input[i])
                    temp_a.insert(8, v_input[i])
                    temp_a.insert(9, sequence[i])
                    temp_a.append("01000000")
                    message = ""
                    for i in temp_a:
                        message += i
                    by_string = bytes.fromhex(message)
                    hash_message = hashlib.sha256(hashlib.sha256(by_string).digest()).digest()
                    array_message.append(hash_message.hex())
                
                array_r = []
                array_s = []
                array_public_key = []

                for i in range(n_txids):
                    #witness first element is the signature
                    signature = witness[i][0]
                    data_wit += "02"
                    sig_len = len(signature)
                    sig_len = sig_len//2
                    sig_len = int_to_hex_compact_size_integer(sig_len)
                    data_wit += sig_len
                    data_wit += signature
                    #discard the first 6 hexadecimal characters, the next 2 hexadecimal characters is the length of r
                    length_r = int(signature[6:8], 16)
                    #next length_r*2 bytes is r
                    r = signature[8:8+length_r*2]
                    #discard the next 2 hexadecimal characters, the next 2 hexadecimal characters is the length of s
                    length_s = int(signature[10+length_r*2:12+length_r*2], 16)
                    #next length_s*2 bytes is s discarding the last 2 hexadecimal characters
                    s = signature[12+length_r*2:12+length_r*2+length_s*2]
                    #witnes second element is the public key
                    public_key = witness[i][1]
                    public_key_len = len(public_key)
                    public_key_len = public_key_len//2
                    public_key_len = int_to_hex_compact_size_integer(public_key_len)
                    data_wit += public_key_len
                    data_wit += public_key
                    array_r.append(r)
                    array_s.append(s)
                    array_public_key.append(public_key)
                data_wit += locktime
                wtxid_h = hashlib.sha256(hashlib.sha256(bytes.fromhex(data_wit)).digest()).digest()
                
                
                for i in range(n_txids):
                    pub_key = array_public_key[i]
                    sig = {'r': int(array_r[i],16), 's': int(array_s[i],16)}
                    mgs = int(array_message[i],16)
                    result = v.verify_signature(pub_key, sig, mgs)
                    if result != True:
                        flag = 1
                
                bytes_string = bytes.fromhex(data_cs)
                hash = hashlib.sha256(hashlib.sha256(bytes_string).digest()).digest()
                if flag == 0:
                    txid_set.add(hash.hex())
                    wtxid_set.add(wtxid_h.hex())
                hash = reverse_byte(hash)
                hash = hashlib.sha256(bytes.fromhex(hash)).digest()
                if hash.hex() + ".json" == filename:
                    temp_segwit += 1
            # If all scriptpubkey_type are v0_p2pkh or v1_p2pkh, print the version number
            
            if all_valid:
                array_s_m = []
                data_c = ""
                counter += 1
                flag = 0
                version = data.get("version")
                locktime = data.get("locktime")
                # Extract txid and vout from each vin in the file
                txids = [vin.get("txid") for vin in data.get("vin", [])]
                vouts = [vin.get("vout") for vin in data.get("vin", [])]
                scriptsig = [vin.get("scriptsig") for vin in data.get("vin", [])]
                sequence = [vin.get("sequence") for vin in data.get("vin", [])]
                value = [vout.get("value") for vout in data.get("vout", [])]
                lockingscript = [vout.get("scriptpubkey") for vout in data.get("vout", [])]
                scriptpubkey = [vin.get("prevout", {}).get("scriptpubkey") for vin in data.get("vin", [])]
                v_in = [vin.get("prevout", {}).get("value") for vin in data.get("vin", [])]

                # Print the txids and vouts
                n_txids = len(txids)
                output_count = len(value)
                
                # Convert the version number to little endian and then to hex
                version_hex = int_to_hex(version)
                #print(f"Version number in little endian: {version_hex}")
                #append the version to the data_c
                data_c += version_hex
                array_s_m.append(version_hex)
                Input_count = int_to_hex_compact_size_integer(n_txids)
                data_c += Input_count
                array_s_m.append(Input_count)
                #print(f"Input Count: {Input_count}")
                for i in range(n_txids):
                    #convert the txid to reverse byte
                    txids[i] = reverse_byte(bytes.fromhex(txids[i]))
                    #print(f"Txid: {txids[i]}")
                    data_c += txids[i]
                    array_s_m.append(txids[i])
                    #convert vout to little endian and then to hex
                    vouts[i] = int_to_hex(vouts[i])
                    #print(f"Vout: {vouts[i]}")
                    data_c += vouts[i]
                    array_s_m.append(vouts[i])
                    
                    #length of scriptsig
                    scriptsig_size = len(scriptsig[i])
                    #scriptsig_size in bytes is half of scriptsig_size in hex, don't make scriptsig_size float
                    scriptsig_size = scriptsig_size//2
                    scriptsig_size = int_to_hex_compact_size_integer(scriptsig_size)
                    #print(f"ScriptSig Size: {scriptsig_size}")
                    data_c += scriptsig_size
                    array_s_m.append("00")
                    #print(f"ScriptSig: {scriptsig[i]}")
                    data_c += scriptsig[i]
                    sequence[i] = int_to_hex(sequence[i])
                    #print(f"Sequence: {sequence[i]}") 
                    data_c += sequence[i]
                    array_s_m.append(sequence[i])
                
                Output_count = int_to_hex_compact_size_integer(output_count)
                #print (f"Output Count: {Output_count}")
                data_c += Output_count
                array_s_m.append(Output_count)
                for i in range(output_count):
                    value[i] = int_to_little_endian_8bytes(int(value[i]))
                    #print(f"Amount: {value[i]}")
                    data_c += value[i]
                    array_s_m.append(value[i])
                    scriptpubkey_size = len(lockingscript[i])
                    scriptpubkey_size = scriptpubkey_size//2
                    scriptpubkey_size = int_to_hex_compact_size_integer(scriptpubkey_size)
                    #print(f"Locking Script Size: {scriptpubkey_size}")
                    data_c += scriptpubkey_size
                    array_s_m.append(scriptpubkey_size)
                    #print(f"Locking Script: {lockingscript[i]}")
                    data_c += lockingscript[i]
                    array_s_m.append(lockingscript[i])
                locktime = int_to_hex(locktime)
                #print(f"Locktime: {locktime}")
                data_c += locktime
                array_s_m.append(locktime)
                #print(f"Data_c: {data_c}")
                #print array_s_m

                array_message = []
                
                #inserting the scriptpubkey into the array
                for i in range(n_txids):
                    temp_a = array_s_m.copy()
                    scriptpubkeylen = len(scriptpubkey[i])
                    scriptpubkeylen = scriptpubkeylen//2
                    scriptpubkeylen = int_to_hex_compact_size_integer(scriptpubkeylen)
                    temp_var = (i+1)*4
                    temp_a[temp_var] = scriptpubkeylen
                    temp_a.insert(temp_var+1, scriptpubkey[i])
                    #append 01000000 the sighash_all to the array
                    temp_a.append("01000000")
                    message = ""
                    #message is the concatenation of all the elements in the array
                    for i in temp_a:
                        #print(f"i: {i}")
                        message += i
                    #double sha256 the message
                    by_string = bytes.fromhex(message)
                    hash_message = hashlib.sha256(hashlib.sha256(by_string).digest()).digest()
                    #print(f"Message: {hash_message.hex()}")
                    array_message.append(hash_message.hex())
                array_r = []
                array_s = []
                array_public_key = []
                #print array_message array
                #extracting the public key and signature from the scriptsig
                for i in range(n_txids):
                    #first 2 hexadecimal (that is the one byte) is the length of the signature in compact size integer
                    length_signature = int(scriptsig[i][:2], 16)
                    #next length_signature*2 bytes is the signature
                    signature = scriptsig[i][2:2+length_signature*2]
                    #print(f"Signature: {signature}")
                    #discard the first 6 hexadecimal characters, the next 2 hexadecimal characters is the length of r
                    length_r = int(signature[6:8], 16)
                    #next length_r*2 bytes is r
                    r = signature[8:8+length_r*2]
                    #print(f"r: {r}")
                    #discard the next 2 hexadecimal characters, the next 2 hexadecimal characters is the length of s
                    length_s = int(signature[10+length_r*2:12+length_r*2], 16)
                    #next length_s*2 bytes is s discarding the last 2 hexadecimal characters
                    s = signature[12+length_r*2:12+length_r*2+length_s*2]
                    #print(f"s: {s}")
                    #next 2 bytes is the length of the public key 
                    length_public_key = int(scriptsig[i][2+length_signature*2:2+length_signature*2+2], 16)
                    #print(f"Length of Public Key: {length_public_key}")
                    #next length_public_key*2 bytes is the public key
                    public_key = scriptsig[i][2+length_signature*2+2:]
                    #print(f"Public Key: {public_key}")
                    array_r.append(r)
                    array_s.append(s)
                    array_public_key.append(public_key)
                #print array_public_key, array_r, array_s, array_message
                """ print(f"Array Public Key: {array_public_key}")
                print(f"Array r: {array_r}")
                print(f"Array s: {array_s}")
                print(f"Array Message: {array_message}")
 """
                for i in range(n_txids):
                    pub_key = array_public_key[i]
                    sig = {'r': int(array_r[i],16), 's': int(array_s[i],16)}
                    mgs = int(array_message[i],16)
                    result = v.verify_signature(pub_key, sig, mgs)
                    if result != True:
                        flag = 1

                if flag == 1:
                    count_valid_tx += 1
                bytes_string = bytes.fromhex(data_c)
                hash = hashlib.sha256(hashlib.sha256(bytes_string).digest()).digest()

                if flag == 0:
                    txid_set.add(hash.hex())
                    wtxid_set.add(hash.hex())
                hash = reverse_byte(hash)
                hash = hashlib.sha256(bytes.fromhex(hash)).digest()
                #print(f"Hash: {hash.hex()}")
                #print(f"File: {filename}")
                #print(f"value: {value}")
                #iterate over the value and convert it into integer using little endian to integer and add it to fee
                temp_out = 0
                for i in value:
                    temp_out += little_endian_to_int(bytes.fromhex(i))
                temp_in = 0
                for i in v_in:
                    temp_in += i
                fee += temp_in - temp_out
                #print("\n")
                #check if hash + .json is equal to the file name or not
                if hash.hex() + ".json" == filename:
                    temp += 1
                


    coutt = counter - count_valid_tx
    #print the txid_set and it's size
    #print(f"Txid Set: {txid_set}")
    #print(f"Size of Txid Set: {len(txid_set)}")
    #print(f"Total number of files with all valid scriptpubkey_type: {counter}")
    #print(f"Total number of files with valid hash: {temp}")
    #print(f"Number of valid transactions: {coutt}")
    #print(f"Total fee: {fee}")
    #print(f"Total number of segwit transactions: {count_segwit_tx}")
    # Convert txid_set to a list
    txid_list = list(txid_set)
    wtxid_list = list(wtxid_set)
    wtxid_list.insert(0,'0000000000000000000000000000000000000000000000000000000000000000')
    
    while len(wtxid_list)>1:
        temp_g = []
        for i in range(0, len(wtxid_list), 2):
            if i+1 < len(wtxid_list):
                # Concatenate two txids, hash them, and convert the result to hexadecimal
                concatenated_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(wtxid_list[i] + wtxid_list[i+1])).digest()).digest().hex()
                temp_g.append(concatenated_hash)
            else:
                #if there is a single txid then concatenate it with itself and hash it
                concatenated_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(wtxid_list[i] + wtxid_list[i])).digest()).digest().hex()
                temp_g.append(concatenated_hash)
        wtxid_list = temp_g
    
    witness_root_hash = wtxid_list[0]
    #print(f"witness root hash : {witness_root_hash}")
    witness_root_hash += '0000000000000000000000000000000000000000000000000000000000000000'
    #hash the witness root hash
    wtxid_commitment = hashlib.sha256(hashlib.sha256(bytes.fromhex(witness_root_hash)).digest()).digest()
    wtxid_commitment = wtxid_commitment.hex()
    wtxid_commitment = '6a24aa21a9ed' + wtxid_commitment
    wtxid_commitment_size = len(wtxid_commitment)
    wtxid_commitment_size = wtxid_commitment_size//2
    wtxid_commitment_size = int_to_hex_compact_size_integer(wtxid_commitment_size)

    #creating coinbase transaction
    ver_c = "01000000"
    marker_c = "00"
    flag = "01"
    input_cc = "01"
    input_c ="0000000000000000000000000000000000000000000000000000000000000000"
    vout_c = "ffffffff"
    scriptsig_size_c = "1b"
    scriptsig_c = "03951a0604f15ccf5609013803062b9b5a0100072f425443432f20"
    sequence_c = "ffffffff"
    output_cc = "02"
    amount = fee + 625000000
    amount = int_to_little_endian_8bytes(amount)
    scriptpubkey_size_c = "19"
    scriptpubkey_c = "76a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac"
    amount_two_c = "0000000000000000"
    stack_c = "01"
    size_stack_c = "20"
    witness_c = "0000000000000000000000000000000000000000000000000000000000000000"
    locktime_c = "00000000"
    
    coinbase = ver_c + marker_c + flag + input_cc + input_c + vout_c + scriptsig_size_c + scriptsig_c + sequence_c + output_cc + amount + scriptpubkey_size_c + scriptpubkey_c + amount_two_c + wtxid_commitment_size + wtxid_commitment + stack_c + size_stack_c + witness_c + locktime_c
    #print(f"Coinbase: {coinbase}")
    #hash256 of the coinbase
    coinbase_txid = ver_c + input_cc + input_c + vout_c + scriptsig_size_c + scriptsig_c + sequence_c + output_cc + amount + scriptpubkey_size_c + scriptpubkey_c + amount_two_c + wtxid_commitment_size + wtxid_commitment + locktime_c
    coinbase_txid = bytes.fromhex(coinbase_txid)
    coinbase_hash = hashlib.sha256(hashlib.sha256(coinbase_txid).digest()).digest()
    #print(f"Coinbase Hash: {coinbase_hash.hex()}")
    

    #merkel root calculation using the txid_set
    merkel_root = []
    txid_list.insert(0,coinbase_hash.hex())
    #make a copy of txid_list
    final_txid_list = txid_list.copy()

    while len(txid_list) > 1:
        temp_t = []
        for i in range(0, len(txid_list), 2):
            if i+1 < len(txid_list):
                # Concatenate two txids, hash them, and convert the result to hexadecimal
                concatenated_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(txid_list[i] + txid_list[i+1])).digest()).digest().hex()
                temp_t.append(concatenated_hash)
            else:
                #if there is a single txid then concatenate it with itself and hash it
                concatenated_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(txid_list[i] + txid_list[i])).digest()).digest().hex()
                temp_t.append(concatenated_hash)
        txid_list = temp_t
    
    # The resulting merkel root will be the first element of txid_list
    merkel_root = txid_list[0]
    #print(f"Merkel Root: {merkel_root}")
    
    #block header creation
    version_bh = "00000020"
    previous_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    current_time = int(time.time())
    current_time = int_to_little_endian_4bytes(current_time)
    bits = "ffff001f"
    nonce = "00000000"
    #iterate over all nonce values till the block hash is less than the target
    target = "0000ffff00000000000000000000000000000000000000000000000000000000"
    target_int = int(target, 16)
    #print(f"Target: {target_int}")
    block_header = version_bh + previous_block_hash + merkel_root + current_time + bits + nonce
    block_header = bytes.fromhex(block_header)
    block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()
    block_hash = reverse_byte(block_hash)
    block_hash_int = int(block_hash,16)
    


    while block_hash_int > target_int and nonce != "ffffffff":
        nonce = int_to_little_endian_4bytes(int(nonce, 16) + 1)
        block_header = version_bh + previous_block_hash + merkel_root + current_time + bits + nonce
        block_header = bytes.fromhex(block_header)
        block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()
        block_hash = reverse_byte(block_hash)
        block_hash_int = int(block_hash, 16)
    
    print(f"{block_header.hex()}")
    print(f"{coinbase}")
    #hash256 of the block header
    #block_header = bytes.fromhex(block_header)
    #block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()
    #print(f"Block Hash: {block_hash}")
    #block_hash_int = int(block_hash, 16)
    #print(f"Block Hash Int: {block_hash_int}")
    #print(f"Nonce: {nonce}")
    #print the final_txid_list in reverse byte order
    for i in range(len(final_txid_list)):
        final_txid_list[i] = reverse_byte(bytes.fromhex(final_txid_list[i]))
        print(final_txid_list[i])
    
    sys.stdout = original_stdout
            


