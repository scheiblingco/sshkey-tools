# Utils

> Auto-generated documentation for [src.sshkey_tools.utils](../../../src/sshkey_tools/utils.py) module.

Utilities for handling keys and certificates

- [Sshkey-tools](../../README.md#sshkey-tools-work-in-progress) / [Modules](../../MODULES.md#sshkey-tools-modules) / `Src` / [Sshkey Tools](index.md#sshkey-tools) / Utils
    - [bytes_to_long](#bytes_to_long)
    - [generate_secure_nonce](#generate_secure_nonce)
    - [long_to_bytes](#long_to_bytes)
    - [md5_fingerprint](#md5_fingerprint)
    - [sha256_fingerprint](#sha256_fingerprint)
    - [sha512_fingerprint](#sha512_fingerprint)

## bytes_to_long

[[find in source code]](../../../src/sshkey_tools/utils.py#L29)

```python
def bytes_to_long(source_bytes: bytes, byteorder: str = 'big') -> int:
```

The opposite of long_to_bytes, converts a byte string to a long integer
Equivalent to paramiko.util.inflate_long()

#### Arguments

- `source_bytes` *bytes* - The byte string to convert
- `byteorder` *str, optional* - Byte order. Defaults to 'big'.

#### Returns

- `int` - Long integer resulting from decoding the byte string

## generate_secure_nonce

[[find in source code]](../../../src/sshkey_tools/utils.py#L44)

```python
def generate_secure_nonce(length: int = 64):
```

 Generates a secure random nonce of the specified length.
Mainly important for ECDSA keys, but is used with all key/certificate types

#### Arguments

- `length` *int, optional* - Length of the nonce. Defaults to 64.

#### Returns

- `str` - Nonce of the specified length

## long_to_bytes

[[find in source code]](../../../src/sshkey_tools/utils.py#L9)

```python
def long_to_bytes(
    source_int: int,
    force_length: int = None,
    byteorder: str = 'big',
) -> bytes:
```

 Converts a positive integer to a byte string conforming with the certificate format.
Equivalent to paramiko.util.deflate_long()

#### Arguments

- `source_int` *int* - Integer to convert
- `force_length` *int, optional* - Pads the resulting bytestring if shorter. Defaults to None.
- `byteorder` *str, optional* - Byte order. Defaults to 'big'.

#### Returns

- `str` - Byte string representing the chosen long integer

## md5_fingerprint

[[find in source code]](../../../src/sshkey_tools/utils.py#L55)

```python
def md5_fingerprint(data: bytes, prefix: bool = True) -> str:
```

Returns an MD5 fingerprint of the given data.

#### Arguments

- `data` *bytes* - The data to fingerprint
- `prefix` *bool, optional* - Whether to prefix the fingerprint with MD5:

#### Returns

- `str` - The fingerprint (OpenSSH style MD5:xx:xx:xx...)

## sha256_fingerprint

[[find in source code]](../../../src/sshkey_tools/utils.py#L69)

```python
def sha256_fingerprint(data: bytes, prefix: bool = True) -> str:
```

Returns a SHA256 fingerprint of the given data.

#### Arguments

- `data` *bytes* - The data to fingerprint
- `prefix` *bool, optional* - Whether to prefix the fingerprint with SHA256:

#### Returns

- `str` - The fingerprint (OpenSSH style SHA256:xx:xx:xx...)

## sha512_fingerprint

[[find in source code]](../../../src/sshkey_tools/utils.py#L83)

```python
def sha512_fingerprint(data: bytes, prefix: bool = True) -> str:
```

Returns a SHA512 fingerprint of the given data.

#### Arguments

- `data` *bytes* - The data to fingerprint
- `prefix` *bool, optional* - Whether to prefix the fingerprint with SHA512:

#### Returns

- `str` - The fingerprint (OpenSSH style SHA256:xx:xx:xx...)
