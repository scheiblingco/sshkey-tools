"""
Utilities for handling keys and certificates
"""
import hashlib as hl
import sys
from base64 import b64encode
from random import randint
from secrets import randbits
from typing import Dict, List, Union
from uuid import uuid4

NoneType = type(None)


def ensure_string(
    obj: Union[str, bytes, list, tuple, set, dict, NoneType],
    encoding: str = "utf-8",
    required: bool = False,
) -> Union[str, List[str], Dict[str, str], NoneType]:
    """Ensure the provided value is or contains a string/strings

    Args:
        obj (_type_): The object to process
        encoding (str, optional): The encoding of the provided strings. Defaults to 'utf-8'.

    Returns:
        Union[str, List[str], Dict[str, str]]: Returns a string, list of strings or
                                               dictionary with strings
    """
    if (obj is None and not required) or isinstance(obj, str):
        return obj
    if isinstance(obj, bytes):
        return obj.decode(encoding)
    if isinstance(obj, (list, tuple, set)):
        return [ensure_string(o, encoding) for o in obj]
    if isinstance(obj, dict):
        return {
            ensure_string(k, encoding): ensure_string(v, encoding)
            for k, v in obj.items()
        }

    raise TypeError(
        f"Expected one of (str, bytes, list, tuple, dict, set), got {type(obj).__name__}."
    )


def ensure_bytestring(
    obj: Union[str, bytes, list, tuple, set, dict, NoneType],
    encoding: str = "utf-8",
    required: bool = None,
) -> Union[str, List[str], Dict[str, str], NoneType]:
    """Ensure the provided value is or contains a bytestring/bytestrings

    Args:
        obj (_type_): The object to process
        encoding (str, optional): The encoding of the provided bytestrings. Defaults to 'utf-8'.

    Returns:
        Union[str, List[str], Dict[str, str]]: Returns a bytestring, list of bytestrings or
                                               dictionary with bytestrings
    """
    if (obj is None and not required) or isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        return obj.encode(encoding)
    if isinstance(obj, (list, tuple, set)):
        return [ensure_bytestring(o, encoding) for o in obj]
    if isinstance(obj, dict):
        return {
            ensure_bytestring(k, encoding): ensure_bytestring(v, encoding)
            for k, v in obj.items()
        }
    raise TypeError(
        f"Expected one of (str, bytes, list, tuple, dict, set), got {type(obj).__name__}."
    )


def concat_to_string(*strs, encoding: str = "utf-8") -> str:
    """Concatenates a list of strings or bytestrings to a single string.

    Args:
        encoding (str, optional): The encoding of the string/s. Defaults to 'utf-8'.
        *strs (List[str, bytes]): The strings to concatenate

    Returns:
        str: Concatenated string
    """
    return "".join(st if st is not None else "" for st in ensure_string(strs, encoding))


def concat_to_bytestring(*strs, encoding: str = "utf-8") -> bytes:
    """Concatenates a list of strings or bytestrings to a single bytestring.

    Args:
        encoding (str, optional): The encoding of the string/s. Defaults to 'utf-8'.
        *strs (List[str, bytes]): The strings to concatenate

    Returns:
        bytes: Concatenated bytestring
    """
    return b"".join(
        st if st is not None else b""
        for st in ensure_bytestring(strs, encoding=encoding)
    )


def random_keyid() -> str:
    """Generates a random Key ID

    Returns:
        str: Random keyid
    """
    return str(uuid4())


def random_serial() -> str:
    """Generates a random serial number

    Returns:
        int: Random serial
    """
    return randint(0, 2**64 - 1)


def long_to_bytes(
    source_int: int, force_length: int = None, byteorder: str = "big"
) -> bytes:
    """Converts a positive integer to a byte string conforming with the certificate format.
        Equivalent to paramiko.util.deflate_long()
    Args:
        source_int (int): Integer to convert
        force_length (int, optional): Pads the resulting bytestring if shorter. Defaults to None.
        byteorder (str, optional): Byte order. Defaults to 'big'.

    Returns:
        str: Byte string representing the chosen long integer
    """
    if source_int < 0:
        raise ValueError(
            "You can only convert positive long integers to bytes with this method"
        )

    if not isinstance(source_int, int):
        raise TypeError(f"Expected integer, got {type(source_int).__name__}.")

    length = (source_int.bit_length() // 8 + 1) if not force_length else force_length
    return source_int.to_bytes(length, byteorder)


def bytes_to_long(source_bytes: bytes, byteorder: str = "big") -> int:
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


def generate_secure_nonce(length: int = 128):
    """Generates a secure random nonce of the specified length.
        Mainly important for ECDSA keys, but is used with all key/certificate types
        https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
        https://datatracker.ietf.org/doc/html/rfc6979
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
    return ("MD5:" if prefix else "") + ":".join(
        a + b for a, b in zip(digest[::2], digest[1::2])
    )


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
    return ("SHA256:" if prefix else "") + b64encode(digest).replace(b"=", b"").decode(
        "utf-8"
    )


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
    return ("SHA512:" if prefix else "") + b64encode(digest).replace(b"=", b"").decode(
        "utf-8"
    )


def join_dicts(*dicts) -> dict:
    """
    Joins two or more dictionaries together.
    In case of duplicate keys, the latest one wins.

    Returns:
        dict: Joined dictionary
    """
    py_version = sys.version_info[0:2]
    return_dict = {}

    if py_version[0] == 3 and py_version[1] > 9:

        for add_dict in dicts:
            return_dict = return_dict | add_dict

        return return_dict

    for add_dict in dicts:
        return_dict = {**return_dict, **add_dict}

    return return_dict
