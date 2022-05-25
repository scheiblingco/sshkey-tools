# Cert

> Auto-generated documentation for [src.sshkey_tools.cert](../../../src/sshkey_tools/cert.py) module.

Contains classes for OpenSSH Certificates, generation, parsing and signing

- [Sshkey-tools](../../README.md#sshkey-tools-work-in-progress) / [Modules](../../MODULES.md#sshkey-tools-modules) / `Src` / [Sshkey Tools](index.md#sshkey-tools) / Cert
    - [DSACertificate](#dsacertificate)
        - [DSACertificate.decode](#dsacertificatedecode)
    - [ECDSACertificate](#ecdsacertificate)
        - [ECDSACertificate.decode](#ecdsacertificatedecode)
    - [ED25519Certificate](#ed25519certificate)
        - [ED25519Certificate.decode](#ed25519certificatedecode)
    - [RSACertificate](#rsacertificate)
        - [RSACertificate.decode](#rsacertificatedecode)
    - [SSHCertificate](#sshcertificate)
        - [SSHCertificate().can_sign](#sshcertificatecan_sign)
        - [SSHCertificate.decode](#sshcertificatedecode)
        - [SSHCertificate.from_bytes](#sshcertificatefrom_bytes)
        - [SSHCertificate.from_file](#sshcertificatefrom_file)
        - [SSHCertificate.from_public_class](#sshcertificatefrom_public_class)
        - [SSHCertificate.from_string](#sshcertificatefrom_string)
        - [SSHCertificate().get_signable_data](#sshcertificateget_signable_data)
        - [SSHCertificate().set_opt](#sshcertificateset_opt)
        - [SSHCertificate().set_opts](#sshcertificateset_opts)
        - [SSHCertificate().set_type](#sshcertificateset_type)
        - [SSHCertificate().sign](#sshcertificatesign)
        - [SSHCertificate().to_bytes](#sshcertificateto_bytes)
        - [SSHCertificate().to_file](#sshcertificateto_file)
        - [SSHCertificate().to_string](#sshcertificateto_string)

#### Raises

- `_EX.SSHCertificateException` - General error in certificate
- `_EX.InvalidCertificateFormatException` - An error with the format of the certificate
- `_EX.InvalidCertificateFieldException` - An invalid field has been added to the certificate
- `_EX.NoPrivateKeyException` - The certificate contains no private key
- `_EX.NotSignedException` - The certificate is not signed and cannot be exported

## DSACertificate

[[find in source code]](../../../src/sshkey_tools/cert.py#L449)

```python
class DSACertificate(SSHCertificate):
    def __init__(
        subject_pubkey: DSAPublicKey,
        ca_privkey: PrivateKey = None,
        **kwargs,
    ):
```

Specific class for DSA/DSS Certificates. Inherits from SSHCertificate

#### See also

- [SSHCertificate](#sshcertificate)

### DSACertificate.decode

[[find in source code]](../../../src/sshkey_tools/cert.py#L462)

```python
@classmethod
def decode(cert_bytes: bytes) -> 'DSACertificate':
```

Decode an existing DSA Certificate

#### Arguments

- `cert_bytes` *bytes* - The base64-decoded bytes for the certificate

#### Returns

- `DSACertificate` - The decoded certificate

## ECDSACertificate

[[find in source code]](../../../src/sshkey_tools/cert.py#L479)

```python
class ECDSACertificate(SSHCertificate):
    def __init__(
        subject_pubkey: ECDSAPublicKey,
        ca_privkey: PrivateKey = None,
        **kwargs,
    ):
```

Specific class for ECDSA Certificates. Inherits from SSHCertificate

#### See also

- [SSHCertificate](#sshcertificate)

### ECDSACertificate.decode

[[find in source code]](../../../src/sshkey_tools/cert.py#L494)

```python
@classmethod
def decode(cert_bytes: bytes) -> 'ECDSACertificate':
```

Decode an existing ECDSA Certificate

#### Arguments

- `cert_bytes` *bytes* - The base64-decoded bytes for the certificate

#### Returns

- `ECDSACertificate` - The decoded certificate

## ED25519Certificate

[[find in source code]](../../../src/sshkey_tools/cert.py#L511)

```python
class ED25519Certificate(SSHCertificate):
    def __init__(
        subject_pubkey: ED25519PublicKey,
        ca_privkey: PrivateKey = None,
        **kwargs,
    ):
```

Specific class for ED25519 Certificates. Inherits from SSHCertificate

#### See also

- [SSHCertificate](#sshcertificate)

### ED25519Certificate.decode

[[find in source code]](../../../src/sshkey_tools/cert.py#L526)

```python
@classmethod
def decode(cert_bytes: bytes) -> 'ED25519Certificate':
```

Decode an existing ED25519 Certificate

#### Arguments

- `cert_bytes` *bytes* - The base64-decoded bytes for the certificate

#### Returns

- `ED25519Certificate` - The decoded certificate

## RSACertificate

[[find in source code]](../../../src/sshkey_tools/cert.py#L416)

```python
class RSACertificate(SSHCertificate):
    def __init__(
        subject_pubkey: RSAPublicKey,
        ca_privkey: PrivateKey = None,
        rsa_alg: RsaAlgs = RsaAlgs.SHA512,
        **kwargs,
    ):
```

Specific class for RSA Certificates. Inherits from SSHCertificate

#### See also

- [SSHCertificate](#sshcertificate)

### RSACertificate.decode

[[find in source code]](../../../src/sshkey_tools/cert.py#L432)

```python
@classmethod
def decode(cert_bytes: bytes) -> 'SSHCertificate':
```

Decode an existing RSA Certificate

#### Arguments

- `cert_bytes` *bytes* - The base64-decoded bytes for the certificate

#### Returns

- `RSACertificate` - The decoded certificate

## SSHCertificate

[[find in source code]](../../../src/sshkey_tools/cert.py#L46)

```python
class SSHCertificate():
    def __init__(
        subject_pubkey: PublicKey = None,
        ca_privkey: PrivateKey = None,
        decoded: dict = None,
        **kwargs,
    ) -> None:
```

General class for SSH Certificates, used for loading and parsing.
To create new certificates, use the respective keytype classes
or the from_public_key classmethod

### SSHCertificate().can_sign

[[find in source code]](../../../src/sshkey_tools/cert.py#L308)

```python
def can_sign() -> bool:
```

Determine if the certificate is ready to be signed

#### Raises

- `...` - Exception from the respective field with error
- `_EX.NoPrivateKeyException` - Private key is missing from class

#### Returns

- `bool` - True/False if the certificate can be signed

### SSHCertificate.decode

[[find in source code]](../../../src/sshkey_tools/cert.py#L137)

```python
@staticmethod
def decode(
    cert_bytes: bytes,
    pubkey_class: _FIELD.PublicKeyField = None,
) -> 'SSHCertificate':
```

Decode an existing certificate and import it into a new object

#### Arguments

- `cert_bytes` *bytes* - The certificate bytes, base64 decoded middle part of the certificate
- `pubkey_field` *_FIELD.PublicKeyField* - Instance of the PublicKeyField class, only needs
    to be set if it can't be detected automatically

#### Raises

- `_EX.InvalidCertificateFormatException` - Invalid or unknown certificate format

#### Returns

- `SSHCertificate` - SSHCertificate child class

### SSHCertificate.from_bytes

[[find in source code]](../../../src/sshkey_tools/cert.py#L212)

```python
@classmethod
def from_bytes(cert_bytes: bytes):
```

Loads an existing certificate from the byte value.

#### Arguments

- `cert_bytes` *bytes* - Certificate bytes, base64 decoded middle part of the certificate

#### Returns

- `SSHCertificate` - SSHCertificate child class

### SSHCertificate.from_file

[[find in source code]](../../../src/sshkey_tools/cert.py#L250)

```python
@classmethod
def from_file(path: str, encoding: str = 'utf-8'):
```

Loads an existing certificate from a file

#### Arguments

- `path` *str* - The path to the certificate file
- `encoding` *str, optional* - Encoding of the file. Defaults to 'utf-8'.

#### Returns

- `SSHCertificate` - SSHCertificate child class

### SSHCertificate.from_public_class

[[find in source code]](../../../src/sshkey_tools/cert.py#L194)

```python
@classmethod
def from_public_class(public_key: PublicKey, **kwargs) -> 'SSHCertificate':
```

Creates a new certificate from a supplied public key

#### Arguments

- `public_key` *PublicKey* - The public key for which to create a certificate

#### Returns

- `SSHCertificate` - SSHCertificate child class

### SSHCertificate.from_string

[[find in source code]](../../../src/sshkey_tools/cert.py#L227)

```python
@classmethod
def from_string(cert_str: Union[str, bytes], encoding: str = 'utf-8'):
```

Loads an existing certificate from a string in the format
[certificate-type] [base64-encoded-certificate] [optional-comment]

#### Arguments

- `cert_str` *str* - The string containing the certificate
- `encoding` *str, optional* - The encoding of the string. Defaults to 'utf-8'.

#### Returns

- `SSHCertificate` - SSHCertificate child class

### SSHCertificate().get_signable_data

[[find in source code]](../../../src/sshkey_tools/cert.py#L335)

```python
def get_signable_data() -> bytes:
```

Gets the signable byte string from the certificate fields

#### Returns

- `bytes` - The data in the certificate which is signed

### SSHCertificate().set_opt

[[find in source code]](../../../src/sshkey_tools/cert.py#L279)

```python
def set_opt(key: str, value):
```

Add information to a field in the certificate

#### Arguments

- `key` *str* - The key to set
- `value` *mixed* - The new value for the field

#### Raises

- `_EX.InvalidCertificateFieldException` - Invalid field

### SSHCertificate().set_opts

[[find in source code]](../../../src/sshkey_tools/cert.py#L301)

```python
def set_opts(**kwargs):
```

Set multiple options at once

### SSHCertificate().set_type

[[find in source code]](../../../src/sshkey_tools/cert.py#L266)

```python
def set_type(pubkey_type: str):
```

Set the type of the public key if not already set automatically
The child classes will set this automatically

#### Arguments

- `pubkey_type` *str* - Public key type, e.g. ssh-rsa-cert-v01@openssh.com

### SSHCertificate().sign

[[find in source code]](../../../src/sshkey_tools/cert.py#L348)

```python
def sign():
```

Sign the certificate

#### Returns

- `SSHCertificate` - The signed certificate class

### SSHCertificate().to_bytes

[[find in source code]](../../../src/sshkey_tools/cert.py#L362)

```python
def to_bytes() -> bytes:
```

Export the signed certificate in byte-format

#### Raises

- `_EX.NotSignedException` - The certificate has not been signed yet

#### Returns

- `bytes` - The certificate bytes

### SSHCertificate().to_file

[[find in source code]](../../../src/sshkey_tools/cert.py#L401)

```python
def to_file(
    path: str,
    comment: Union[str, bytes] = None,
    encoding: str = 'utf-8',
):
```

Saves the certificate to a file

#### Arguments

- `path` *str* - The path of the file to save to
comment (Union[str, bytes], optional): Comment to add to the certificate end.
                                       Defaults to None.
- `encoding` *str, optional* - Encoding for the file. Defaults to 'utf-8'.

### SSHCertificate().to_string

[[find in source code]](../../../src/sshkey_tools/cert.py#L380)

```python
def to_string(
    comment: Union[str, bytes] = None,
    encoding: str = 'utf-8',
) -> str:
```

Export the signed certificate to a string, ready to be written to file

#### Arguments

comment (Union[str, bytes], optional): Comment to add to the string. Defaults to None.
- `encoding` *str, optional* - Encoding to use for the string. Defaults to 'utf-8'.

#### Returns

- `str` - Certificate string
