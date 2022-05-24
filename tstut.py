from struct import pack, unpack
from secrets import randbits


# Generates a nonce from the secrets module
# Generally more secure than the random library
def generate_secure_nonce(bits: int) -> str:
    return str(randbits(bits))

def long_to_bytes(source_int: int, force_length: int = False, byteorder: str = 'big') -> bytes:
    if source_int < 0:
        raise ValueError("You can only convert positive long integers to bytes")
    
    length = (source_int.bit_length() // 8 + 1) if not force_length else force_length
    return source_int.to_bytes(length, byteorder)
    
def bytes_to_long(source_bytes: bytes, byteorder: str = 'big') -> int:
    return int.from_bytes(source_bytes, byteorder)
    
def encode_string(source_string, encoding: str = 'utf-8') -> bytes:
    if isinstance(source_string, str):
        source_string = source_string.encode(encoding)
        
    if isinstance(source_string, bytes):
        return pack('>I', len(source_string)) + source_string
    else:
        raise TypeError("Expected unicode or bytes, got {!r}. Try specifying a different encoding.".format(source_string))

def encode_boolean(source_bool: bool) -> bytes:
    return pack("B", 1) if source_bool else pack("B", 0)

def encode_int(source_int: int) -> bytes:
    return pack('>I', source_int)

def encode_int64(source_int: int) -> bytes:
    return pack('>Q', source_int)

def encode_mpint(source_int: int) -> bytes:
    if source_int < 0:
        raise ValueError("MPInts must be positive")
    
    return encode_string(long_to_bytes(source_int))

def encode_list(source_list: list, null_separator: bool = False):
    if null_separator and len(source_list) > 0:
        return encode_string(encode_string('').join([
            encode_string(x) for x in source_list
        ]) + encode_string(''))
    else:
        return encode_string(b''.join([encode_string(x) for x in source_list]))

def encode_rsa_signature(sig: bytes, type: bytes) -> bytes:
    return encode_string(encode_string(type) + encode_string(sig))

def encode_dsa_signature(sig_r: bytes, sig_s: bytes, curve: str) -> bytes:
    signature = encode_mpint(sig_r) + encode_mpint(sig_s)
    return encode_string(encode_string(curve) + encode_string(signature))

def encode_dss_signature(sig_r: bytes, sig_s: bytes, type: str) -> bytes:
    signature = encode_string(type)
    signature += encode_string(long_to_bytes(sig_r, 20) + long_to_bytes(sig_s, 20))
    return encode_string(signature)

def decode_string(data: bytes) -> tuple:
    size = unpack('>I', data[:4])[0]+4
    return data[4:size], data[size:]

def decode_int(data: bytes) -> tuple:
    return int(unpack('>I', data[:4])[0]), data[4:]

def decode_int64(data: bytes) -> tuple:
    return int(unpack('>Q', data[:8])[0]), data[8:]

def decode_mpint(data: bytes) -> tuple:
    mpint_str, data = decode_string(data)
    return bytes_to_long(mpint_str), data

def decode_list(data: bytes, null_separator: bool = False) -> tuple:
    layer_one, data = decode_string(data)
        
    lst = []
    while len(layer_one) > 0:
        elem, layer_one = decode_string(layer_one)
        if not null_separator:
            lst.append(elem)
        else:
            lst.append(elem) if elem != b'' else None
        
    return lst, data

def decode_dsa_signature(data: bytes) -> tuple:
    signature = {}
    layer_one, data = decode_string(data)
    
    signature['curve'], layer_one = decode_string(layer_one)
    encoded_sig, _ = decode_string(layer_one)
    signature['r'], encoded_sig = decode_mpint(encoded_sig)
    signature['s'] = decode_mpint(encoded_sig)[0]
    
    return signature, data

def decode_dss_signature(data: bytes) -> tuple:
    signature = {}
    layer_one, data = decode_string(data)
    
    signature['type'], layer_one = decode_string(layer_one)
    encoded_sig, _ = decode_string(layer_one)
    signature['r'] = bytes_to_long(encoded_sig[:20])
    signature['s'] = bytes_to_long(encoded_sig[20:])
    return signature, data

def decode_rsa_signature(data: bytes) -> tuple:
    signature = {}
    layer_one, data = decode_string(data)
    
    signature['type'], layer_one = decode_string(layer_one)
    signature['data'] = decode_string(layer_one)[0]
    
    return signature, data