import ecdsa

def inverse_mod(s, n):
    # Calculate the modular multiplicative inverse of s modulo n
    return pow(s, -1, n)

def multiply(point, scalar):
    # Scalar multiplication of a point on the curve
    return point * scalar

def add(point1, point2):
    # Add two points together
    return point1 + point2

def verify(public_key, signature, hash_value, curve=ecdsa.SECP256k1):
    # Convert signature components to integers
    r = signature['r']
    s = signature['s']
    
    # Calculate inverse of s modulo the curve order
    inv_s = inverse_mod(s, curve.order)
    
    # Calculate point1: G * (s^-1 * hash)
    point1 = multiply(curve.generator, inv_s * hash_value)
    
    # Calculate point2: public_key * (s^-1 * r)
    point2 = multiply(public_key, inv_s * r)
    
    # Add point1 and point2
    point3 = add(point1, point2)
    
    # Check if x-coordinate of point3 matches r
    return point3.x() == r

def verify_signature(public_key_hex, signature, hash_value):
    # Convert the hexadecimal public key to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)

    # Instantiate the verifying key
    public_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1).pubkey.point

    # Verify the signature
    return verify(public_key, signature, hash_value)

