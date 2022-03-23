"""
Includes tools for encoding and decoding OpenSSH Certificates and public/private keypairs
"""

from struct import pack
from secrets import randbits

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
    return pack('>I', source_int)

def encode_int64(source_int: int) -> bytes:
    """Encodes a 64-bit integer value to a packed byte string

    Args:
        source_int (int): Integer to be packed

    Returns:
        bytes: Packed byte string containing integer
    """
    return pack('>Q', source_int)

def encode_mpint(source_int: int) -> bytes:
    """Encodes a multiprecision integer (integer longer than 64bit)
       into a packed byte string

    Args:
        source_int (int): Large integer

    Returns:
        bytes: Packed byte string containing integer
    """
    