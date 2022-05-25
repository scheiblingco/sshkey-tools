"""
Utilities for handling keys and certificates
"""
from secrets import randbits
from base64 import b64encode
import hashlib as hl


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

def generate_secure_nonce(length: int = 64):
    """ Generates a secure random nonce of the specified length.
        Mainly important for ECDSA keys, but is used with all key/certificate types
    Args:
        length (int, optional): Length of the nonce. Defaults to 64.

    Returns:
        str: Nonce of the specified length
    """
    return str(randbits(length))

def md5_fingerprint(data: bytes, prefix: bool = True) -> str:
    """
    Returns an MD5 fingerprint of the given data.

    Args:
        data (bytes): The data to fingerprint
        prefix (bool, optional): Whether to prefix the fingerprint with MD5:

    Returns:
        str: The fingerprint (OpenSSH style MD5:xx:xx:xx...)
    """
    digest = hl.md5(data).hexdigest()
    return ("MD5:" if prefix else "") + ':'.join(a + b for a, b in zip(digest[::2], digest[1::2]))

def sha256_fingerprint(data: bytes, prefix: bool = True) -> str:
    """
    Returns a SHA256 fingerprint of the given data.

    Args:
        data (bytes): The data to fingerprint
        prefix (bool, optional): Whether to prefix the fingerprint with SHA256:

    Returns:
        str: The fingerprint (OpenSSH style SHA256:xx:xx:xx...)
    """
    digest = hl.sha256(data).digest()
    return ("SHA256:" if prefix else "") + b64encode(digest).replace(b"=", b"").decode('utf-8')

def sha512_fingerprint(data: bytes, prefix: bool = True) -> str:
    """
    Returns a SHA512 fingerprint of the given data.

    Args:
        data (bytes): The data to fingerprint
        prefix (bool, optional): Whether to prefix the fingerprint with SHA512:

    Returns:
        str: The fingerprint (OpenSSH style SHA256:xx:xx:xx...)
    """
    digest = hl.sha512(data).digest()
    return ("SHA512:" if prefix else "") + b64encode(digest).replace(b"=", b"").decode('utf-8')
