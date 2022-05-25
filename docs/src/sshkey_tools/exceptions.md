# Exceptions

> Auto-generated documentation for [src.sshkey_tools.exceptions](../../../src/sshkey_tools/exceptions.py) module.

Exceptions thrown by sshkey_tools

- [Sshkey-tools](../../README.md#sshkey-tools-work-in-progress) / [Modules](../../MODULES.md#sshkey-tools-modules) / `Src` / [Sshkey Tools](index.md#sshkey-tools) / Exceptions
    - [InsecureNonceException](#insecurenonceexception)
    - [IntegerOverflowException](#integeroverflowexception)
    - [InvalidCertificateFieldException](#invalidcertificatefieldexception)
    - [InvalidCertificateFormatException](#invalidcertificateformatexception)
    - [InvalidCurveException](#invalidcurveexception)
    - [InvalidDataException](#invaliddataexception)
    - [InvalidFieldDataException](#invalidfielddataexception)
    - [InvalidHashException](#invalidhashexception)
    - [InvalidKeyException](#invalidkeyexception)
    - [InvalidKeyFormatException](#invalidkeyformatexception)
    - [NoPrivateKeyException](#noprivatekeyexception)
    - [NotSignedException](#notsignedexception)
    - [SSHCertificateException](#sshcertificateexception)
    - [SignatureNotPossibleException](#signaturenotpossibleexception)

## InsecureNonceException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L38)

```python
class InsecureNonceException(ValueError):
```

Raised when the nonce is too short to be secure.
Especially important for ECDSA, see:
https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a

## IntegerOverflowException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L45)

```python
class IntegerOverflowException(ValueError):
```

Raised when the integer is too large to be represented

## InvalidCertificateFieldException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L33)

```python
class InvalidCertificateFieldException(KeyError):
```

Raised when the certificate field is not found/not editable

## InvalidCertificateFormatException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L63)

```python
class InvalidCertificateFormatException(ValueError):
```

Raised when the format of the certificate is invalid

## InvalidCurveException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L15)

```python
class InvalidCurveException(ValueError):
```

Raised when the ECDSA curve
is not supported.

## InvalidDataException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L27)

```python
class InvalidDataException(ValueError):
```

Raised when the data passed
to a function is invalid

## InvalidFieldDataException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L10)

```python
class InvalidFieldDataException(ValueError):
```

Raised when a field contains invalid data

## InvalidHashException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L21)

```python
class InvalidHashException(ValueError):
```

Raised when the hash type is
not available

## InvalidKeyException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L5)

```python
class InvalidKeyException(ValueError):
```

Raised when a key is invalid.

## InvalidKeyFormatException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L68)

```python
class InvalidKeyFormatException(ValueError):
```

Raised when the format of the chosen key is invalid,
normally when trying to use a private key instead of
a public key or vice versa

## NoPrivateKeyException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L75)

```python
class NoPrivateKeyException(ValueError):
```

Raised when no private key is present to sign with

## NotSignedException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L57)

```python
class NotSignedException(ValueError):
```

Raised when trying to export a certificate that has not been
signed by a private key

## SSHCertificateException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L80)

```python
class SSHCertificateException(ValueError):
```

Raised when the SSH Certificate is invalid

## SignatureNotPossibleException

[[find in source code]](../../../src/sshkey_tools/exceptions.py#L50)

```python
class SignatureNotPossibleException(ValueError):
```

Raised when the signature of a certificate is not possible,
usually because no private key has been loaded or a required
field is empty.
