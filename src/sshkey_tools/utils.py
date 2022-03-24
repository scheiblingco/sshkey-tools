"""
Includes tools for encoding and decoding OpenSSH Certificates and public/private keypairs
"""

from struct import pack, unpack
from secrets import randbits
from typing import Union, List, Tuple

StrOrBytes = Union[str, bytes]
StrListOrTuple = Union[List[StrOrBytes], Tuple[StrOrBytes]]

# OpenSSH Certificate utilities
def generate_secure_nonce(length: int = 64):
    """ Generates a secure random nonce of the specified length.
        Mainly important for ECDSA keys, but is used with all key/certificate types
    Args:
        length (int, optional): Length of the nonce. Defaults to 64.

    Returns:
        str: Nonce of the specified length
    """
    return str(randbits(length))

def long_to_bytes(source_int: int, force_length: int = None, byteorder: str = 'big') -> bytes:
    """ Converts a positive integer to a byte string conforming with the certificate format.
        Equivalent to paramiko.util.deflate_long()
    Args:
        source_int (int): Integer to convert
        force_length (int, optional): Pads the resulting bytestring if shorter. Defaults to None.
        byteorder (str, optional): Byte order. Defaults to 'big'.

    Returns:
        str: Byte string representing the chosen long integer
    """
    if source_int < 0:
        raise ValueError("You can only convert positive long integers to bytes with this method")

    if not isinstance(source_int, int):
        raise TypeError(f"Expected integer, got {type(source_int).__name__}.")

    length = (source_int.bit_length() // 8 + 1) if not force_length else force_length
    return source_int.to_bytes(length, byteorder)

def bytes_to_long(source_bytes: bytes, byteorder: str = 'big') -> int:
    """The opposite of long_to_bytes, converts a byte string to a long integer
       Equivalent to paramiko.util.inflate_long()
    Args:
        source_bytes (bytes): The byte string to convert
        byteorder (str, optional): Byte order. Defaults to 'big'.

    Returns:
        int: Long integer resulting from decoding the byte string
    """
    if not isinstance(source_bytes, bytes):
        raise TypeError(f"Expected bytes, got {type(source_bytes).__name__}.")

    return int.from_bytes(source_bytes, byteorder)


# Byte encoding utilities
def encode_boolean(source_bool: bool) -> bytes:
    """Encodes a boolean value to a byte string
    Args:
        source_bool (bool): Boolean to encode

    Returns:
        str: Packed byte representing the boolean
    """
    return pack('B', 1 if source_bool else 0)

def encode_int(source_int: int) -> bytes:
    """Encodes a 32-bit integer value to a packed byte string

    Args:
        source_int (int): Integer to be packed

    Returns:
        bytes: Packed byte string containing integer
    """
    if not isinstance(source_int, int):
        raise TypeError(f"Expected integer, got {type(source_int).__name__}.")

    return pack('>I', source_int)

def encode_int64(source_int: int) -> bytes:
    """Encodes a 64-bit integer value to a packed byte string

    Args:
        source_int (int): Integer to be packed

    Returns:
        bytes: Packed byte string containing integer
    """
    if not isinstance(source_int, int):
        raise TypeError(f"Expected integer, got {type(source_int).__name__}.")

    return pack('>Q', source_int)


def encode_mpint(source_int: int) -> bytes:
    """Encodes a multiprecision integer (integer longer than 64bit)
       into a packed byte string

    Args:
        source_int (int): Large integer

    Returns:
        bytes: Packed byte string containing integer
    """
    if not isinstance(source_int, int):
        raise TypeError(f"Expected integer, got {type(source_int).__name__}.")

    return encode_string(long_to_bytes(source_int))


def encode_string(source_string: StrOrBytes, encoding: str = 'utf-8') -> bytes:
    """Encodes a string or bytestring into a packed byte string

    Args:
        source_string (str, bytes): The string to encode

    Returns:
        bytes: Packed byte string containing the source data
    """
    if isinstance(source_string, str):
        source_string = source_string.encode(encoding)

    if isinstance(source_string, bytes):
        return pack('>I', len(source_string)) + source_string

    raise TypeError(f"Expected unicode or bytes, got {type(source_string).__name__}.")

def encode_list(source_list: StrListOrTuple, null_separator: bool = None) -> bytes:
    """Encodes a list or tuple to a byte string

    Args:
        source_list (list): list of strings
        null_separator (bool, optional): Insert blank string string between items. Default None

    Returns:
        bytes: Packed byte string containing the source data
    """
    if sum([ not isinstance(item, (str, bytes)) for item in source_list]) > 0:
        raise TypeError("Expected list or tuple containing strings or bytes")

    if null_separator and len(source_list) > 0:
        return encode_string(encode_string('').join([
            encode_string(x) for x in source_list
        ]) + encode_string(''))

    return encode_string(b''.join([encode_string(x) for x in source_list]))

def encode_rsa_signature(signature: bytes, cert_type: StrOrBytes = 'ssh-rsa') -> bytes:
    """Encodes an RSA signature to the OpenSSH Certificate format

    Args:
        signature (bytes): The signature data
        cert_type (str, bytes): The type, default ssh-rsa

    Returns:
        _type_: Byte string with the encoded certificate
    """
    return encode_string( encode_string(cert_type) + encode_string(signature) )

def encode_dss_signature(r_value: bytes, s_value: bytes, cert_type: StrOrBytes = 'ssh-dss') ->bytes:
    """Encodes a DSS signature fto the OpenSSH Certificate format

    Args:
        signature_r (bytes): The decoded signature R-value
        signature_s (bytes): The decoded signature S-value
        type (str): The certificate type, default: ssh-dss

    Returns:
        bytes: Byte string with the encoded certificate
    """
    return encode_string(
            encode_string(cert_type) +
            encode_string(
                long_to_bytes(r_value, 20) +
                long_to_bytes(s_value, 20)
            )
    )

def encode_ecdsa_signature(signature_r: bytes, signature_s: bytes, curve: StrOrBytes) -> bytes:
    """Encodes an ECDSA signature to the OpenSSH Certificate format

    Args:
        signature_r (bytes): The decoded signature R-value
        signature_s (bytes): The decoded signature S-value
        curve (StrOrBytes): The EC-curve and hash used (e.g. ecdsa-sha2-nistp256)

    Returns:
        bytes: Bytestring with the encoded certificate
    """
    return encode_string(
        encode_string(curve) +
        encode_string(
            encode_mpint(signature_r) +
            encode_mpint(signature_s)
        )
    )


def decode_string(data: bytes) -> tuple:
    """Decode a string from a block of bytes
       Returns the string and the remainder of the block

    Args:
        data (bytes): Block of bytes

    Returns:
        tuple(bytes, str): string, remainder of block
    """
    size = unpack('>I', data[:4])[0]+4
    return data[4:size], data[size:]
