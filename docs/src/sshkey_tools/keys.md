# Keys

> Auto-generated documentation for [src.sshkey_tools.keys](../../../src/sshkey_tools/keys.py) module.

Classes for handling SSH public/private keys

- [Sshkey-tools](../../README.md#sshkey-tools-work-in-progress) / [Modules](../../MODULES.md#sshkey-tools-modules) / `Src` / [Sshkey Tools](index.md#sshkey-tools) / Keys
    - [DSAPrivateKey](#dsaprivatekey)
        - [DSAPrivateKey.from_numbers](#dsaprivatekeyfrom_numbers)
        - [DSAPrivateKey.generate](#dsaprivatekeygenerate)
        - [DSAPrivateKey().sign](#dsaprivatekeysign)
    - [DSAPublicKey](#dsapublickey)
        - [DSAPublicKey.from_numbers](#dsapublickeyfrom_numbers)
    - [ECDSAPrivateKey](#ecdsaprivatekey)
        - [ECDSAPrivateKey.from_numbers](#ecdsaprivatekeyfrom_numbers)
        - [ECDSAPrivateKey.generate](#ecdsaprivatekeygenerate)
        - [ECDSAPrivateKey().sign](#ecdsaprivatekeysign)
    - [ECDSAPublicKey](#ecdsapublickey)
        - [ECDSAPublicKey.from_numbers](#ecdsapublickeyfrom_numbers)
    - [ED25519PrivateKey](#ed25519privatekey)
        - [ED25519PrivateKey.from_raw_bytes](#ed25519privatekeyfrom_raw_bytes)
        - [ED25519PrivateKey.generate](#ed25519privatekeygenerate)
        - [ED25519PrivateKey().raw_bytes](#ed25519privatekeyraw_bytes)
        - [ED25519PrivateKey().sign](#ed25519privatekeysign)
    - [ED25519PublicKey](#ed25519publickey)
        - [ED25519PublicKey.from_raw_bytes](#ed25519publickeyfrom_raw_bytes)
    - [EcdsaCurves](#ecdsacurves)
    - [FingerprintHashes](#fingerprinthashes)
    - [PrivateKey](#privatekey)
        - [PrivateKey.from_class](#privatekeyfrom_class)
        - [PrivateKey.from_file](#privatekeyfrom_file)
        - [PrivateKey.from_string](#privatekeyfrom_string)
        - [PrivateKey().to_bytes](#privatekeyto_bytes)
        - [PrivateKey().to_file](#privatekeyto_file)
        - [PrivateKey().to_string](#privatekeyto_string)
    - [PublicKey](#publickey)
        - [PublicKey.from_class](#publickeyfrom_class)
        - [PublicKey.from_file](#publickeyfrom_file)
        - [PublicKey.from_string](#publickeyfrom_string)
        - [PublicKey().get_fingerprint](#publickeyget_fingerprint)
        - [PublicKey().raw_bytes](#publickeyraw_bytes)
        - [PublicKey().serialize](#publickeyserialize)
        - [PublicKey().to_file](#publickeyto_file)
        - [PublicKey().to_string](#publickeyto_string)
    - [RSAPrivateKey](#rsaprivatekey)
        - [RSAPrivateKey.from_numbers](#rsaprivatekeyfrom_numbers)
        - [RSAPrivateKey.generate](#rsaprivatekeygenerate)
        - [RSAPrivateKey().sign](#rsaprivatekeysign)
    - [RSAPublicKey](#rsapublickey)
        - [RSAPublicKey.from_numbers](#rsapublickeyfrom_numbers)
    - [RsaAlgs](#rsaalgs)

## DSAPrivateKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L611)

```python
class DSAPrivateKey(PrivateKey):
    def __init__(key: _DSA.DSAPrivateKey):
```

Class for holding DSA private keys

#### See also

- [PrivateKey](#privatekey)

### DSAPrivateKey.from_numbers

[[find in source code]](../../../src/sshkey_tools/keys.py#L624)

```python
@classmethod
def from_numbers(p: int, q: int, g: int, y: int, x: int) -> 'DSAPrivateKey':
```

Creates a new DSAPrivateKey object from parameters and public/private numbers

#### Arguments

- `p` *int* - P parameter, the prime modulus
- `q` *int* - Q parameter, the order of the subgroup
- `g` *int* - G parameter, the generator
- `y` *int* - The public number Y
- `x` *int* - The private number X

#### Returns

- `_type_` - _description_

### DSAPrivateKey.generate

[[find in source code]](../../../src/sshkey_tools/keys.py#L661)

```python
@classmethod
def generate(key_size: int = 4096) -> 'DSAPrivateKey':
```

Generate a new DSA private key

#### Arguments

- `key_size` *int, optional* - Number of key bytes. Defaults to 4096.

#### Returns

- `DSAPrivateKey` - An instance of DSAPrivateKey

### DSAPrivateKey().sign

[[find in source code]](../../../src/sshkey_tools/keys.py#L678)

```python
def sign(data: bytes):
```

Signs a block of data and returns the signature

#### Arguments

- `data` *bytes* - Block of byte data to sign

#### Returns

- `bytes` - The signature bytes

## DSAPublicKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L559)

```python
class DSAPublicKey(PublicKey):
    def __init__(
        key: _DSA.DSAPublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
        serialized: bytes = None,
    ):
```

Class for holding DSA public keys

#### See also

- [PublicKey](#publickey)

### DSAPublicKey.from_numbers

[[find in source code]](../../../src/sshkey_tools/keys.py#L579)

```python
@classmethod
def from_numbers(p: int, q: int, g: int, y: int) -> 'DSAPublicKey':
```

Create a DSA public key from public numbers and parameters

#### Arguments

- `p` *int* - P parameter, the prime modulus
- `q` *int* - Q parameter, the order of the subgroup
- `g` *int* - G parameter, the generator
- `y` *int* - The public number Y

#### Returns

- `DSAPublicKey` - An instance of DSAPublicKey

## ECDSAPrivateKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L747)

```python
class ECDSAPrivateKey(PrivateKey):
    def __init__(key: _ECDSA.EllipticCurvePrivateKey):
```

Class for holding ECDSA private keys

#### See also

- [PrivateKey](#privatekey)

### ECDSAPrivateKey.from_numbers

[[find in source code]](../../../src/sshkey_tools/keys.py#L760)

```python
@classmethod
def from_numbers(
    curve: Union[str, _ECDSA.EllipticCurve],
    x: int,
    y: int,
    private_value: int,
):
```

Creates a new ECDSAPrivateKey object from parameters and public/private numbers

#### Arguments

curve Union[str, _ECDSA.EllipticCurve]: Curve used by the key
- `x` *int* - The affine X component of the public point
- `y` *int* - The affine Y component of the public point
- `private_value` *int* - The private value

#### Returns

- `_type_` - _description_

### ECDSAPrivateKey.generate

[[find in source code]](../../../src/sshkey_tools/keys.py#L800)

```python
@classmethod
def generate(curve: EcdsaCurves = EcdsaCurves.P521):
```

Generate a new ECDSA private key

#### Arguments

- `curve` *EcdsaCurves* - Which curve to use. Default secp521r1

#### Returns

- `ECDSAPrivateKey` - An instance of ECDSAPrivateKey

#### See also

- [EcdsaCurves](#ecdsacurves)

### ECDSAPrivateKey().sign

[[find in source code]](../../../src/sshkey_tools/keys.py#L817)

```python
def sign(data: bytes):
```

Signs a block of data and returns the signature

#### Arguments

- `data` *bytes* - Block of byte data to sign

#### Returns

- `bytes` - The signature bytes

## ECDSAPublicKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L693)

```python
class ECDSAPublicKey(PublicKey):
    def __init__(
        key: _ECDSA.EllipticCurvePublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
        serialized: bytes = None,
    ):
```

Class for holding ECDSA public keys

#### See also

- [PublicKey](#publickey)

### ECDSAPublicKey.from_numbers

[[find in source code]](../../../src/sshkey_tools/keys.py#L712)

```python
@classmethod
def from_numbers(
    curve: Union[str, _ECDSA.EllipticCurve],
    x: int,
    y: int,
) -> 'ECDSAPublicKey':
```

Create an ECDSA public key from public numbers and parameters

#### Arguments

curve Union[str, _ECDSA.EllipticCurve]: Curve used by the key
- `x` *int* - The affine X component of the public point
- `y` *int* - The affine Y component of the public point

#### Returns

- `ECDSAPublicKey` - An instance of ECDSAPublicKey

## ED25519PrivateKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L868)

```python
class ED25519PrivateKey(PrivateKey):
    def __init__(key: _ED25519.Ed25519PrivateKey):
```

Class for holding ED25519 private keys

#### See also

- [PrivateKey](#privatekey)

### ED25519PrivateKey.from_raw_bytes

[[find in source code]](../../../src/sshkey_tools/keys.py#L880)

```python
@classmethod
def from_raw_bytes(raw_bytes: bytes) -> 'ED25519PrivateKey':
```

Load an ED25519 private key from raw bytes

#### Arguments

- `raw_bytes` *bytes* - The raw bytes of the key

#### Returns

- `ED25519PrivateKey` - Instance of ED25519PrivateKey

### ED25519PrivateKey.generate

[[find in source code]](../../../src/sshkey_tools/keys.py#L897)

```python
@classmethod
def generate() -> 'ED25519PrivateKey':
```

Generates a new ED25519 Private Key

#### Returns

- `ED25519PrivateKey` - Instance of ED25519PrivateKey

### ED25519PrivateKey().raw_bytes

[[find in source code]](../../../src/sshkey_tools/keys.py#L909)

```python
def raw_bytes() -> bytes:
```

Export the raw key bytes

#### Returns

- `bytes` - The key bytes

### ED25519PrivateKey().sign

[[find in source code]](../../../src/sshkey_tools/keys.py#L922)

```python
def sign(data: bytes):
```

Signs a block of data and returns the signature

#### Arguments

- `data` *bytes* - Block of byte data to sign

#### Returns

- `bytes` - The signature bytes

## ED25519PublicKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L833)

```python
class ED25519PublicKey(PublicKey):
    def __init__(
        key: _ED25519.Ed25519PublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
        serialized: bytes = None,
    ):
```

Class for holding ED25519 public keys

#### See also

- [PublicKey](#publickey)

### ED25519PublicKey.from_raw_bytes

[[find in source code]](../../../src/sshkey_tools/keys.py#L851)

```python
@classmethod
def from_raw_bytes(raw_bytes: bytes) -> 'ED25519PublicKey':
```

Load an ED25519 public key from raw bytes

#### Arguments

- `raw_bytes` *bytes* - The raw bytes of the key

#### Returns

- `ED25519PublicKey` - Instance of ED25519PublicKey

## EcdsaCurves

[[find in source code]](../../../src/sshkey_tools/keys.py#L84)

```python
class EcdsaCurves(Enum):
```

ECDSA Curves

## FingerprintHashes

[[find in source code]](../../../src/sshkey_tools/keys.py#L92)

```python
class FingerprintHashes(Enum):
```

Fingerprint hashes

## PrivateKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L260)

```python
class PrivateKey():
    def __init__(
        key: PrivkeyClasses,
        public_key: PublicKey,
        **kwargs,
    ) -> None:
```

Class for handling SSH Private keys

#### See also

- [PrivkeyClasses](#privkeyclasses)
- [PublicKey](#publickey)

### PrivateKey.from_class

[[find in source code]](../../../src/sshkey_tools/keys.py#L280)

```python
@classmethod
def from_class(key_class: PrivkeyClasses) -> 'PrivateKey':
```

Import an SSH Private key from a cryptography key class

#### Arguments

- `key_class` *PrivkeyClasses* - A cryptography private key class

#### Raises

- `_EX.InvalidKeyException` - Invalid private key

#### Returns

- `PrivateKey` - One of the PrivateKey child classes

#### See also

- [PrivkeyClasses](#privkeyclasses)

### PrivateKey.from_file

[[find in source code]](../../../src/sshkey_tools/keys.py#L330)

```python
@classmethod
def from_file(
    path: str,
    password: Union[str, bytes] = None,
    encoding: str = 'utf-8',
) -> 'PrivateKey':
```

Loads an SSH private key from a file

#### Arguments

- `path` *str* - The path to the file
- `password` *str, optional* - The encryption password. Defaults to None.
- `encoding(str,` *optional)* - The encoding of the file. Defaults to 'utf-8'.

#### Returns

- `PrivateKey` - Any of the PrivateKey child classes

### PrivateKey.from_string

[[find in source code]](../../../src/sshkey_tools/keys.py#L299)

```python
@classmethod
def from_string(
    key_data: Union[str, bytes],
    password: Union[str, bytes] = None,
    encoding: str = 'utf-8',
) -> 'PrivateKey':
```

Loads an SSH private key from a string containing the key data

#### Arguments

key_data (Union[str, bytes]): The string containing the key data
- `password` *str, optional* - The password for the private key. Defaults to None.
- `encoding(str,` *optional)* - The encoding of the file. Defaults to 'utf-8'.

#### Returns

- `PrivateKey` - Any of the PrivateKey child classes

### PrivateKey().to_bytes

[[find in source code]](../../../src/sshkey_tools/keys.py#L351)

```python
def to_bytes(password: Union[str, bytes] = None) -> bytes:
```

Exports the private key to a byte string

#### Arguments

password (Union[str, bytes], optional): The password to set for the key.
                                        Defaults to None.

#### Returns

- `bytes` - The private key in PEM format

### PrivateKey().to_file

[[find in source code]](../../../src/sshkey_tools/keys.py#L389)

```python
def to_file(
    path: str,
    password: Union[str, bytes] = None,
    encoding: str = 'utf-8',
) -> None:
```

Exports the private key to a file

#### Arguments

password (Union[str, bytes], optional): The password to set for the key.
                                        Defaults to None.

#### Returns

- `bytes` - The private key in PEM format

### PrivateKey().to_string

[[find in source code]](../../../src/sshkey_tools/keys.py#L375)

```python
def to_string(
    password: Union[str, bytes] = None,
    encoding: str = 'utf-8',
) -> str:
```

Exports the private key to a string

#### Arguments

password (Union[str, bytes], optional): The password to set for the key.
                                        Defaults to None.
- `encoding` *str, optional* - The encoding of the string. Defaults to 'utf-8'.

#### Returns

- `bytes` - The private key in PEM format

## PublicKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L100)

```python
class PublicKey():
    def __init__(
        key: PrivkeyClasses = None,
        comment: Union[str, bytes] = None,
        **kwargs,
    ) -> None:
```

Class for handling SSH public keys

#### See also

- [PrivkeyClasses](#privkeyclasses)

### PublicKey.from_class

[[find in source code]](../../../src/sshkey_tools/keys.py#L122)

```python
@classmethod
def from_class(
    key_class: PubkeyClasses,
    comment: Union[str, bytes] = None,
    key_type: Union[str, bytes] = None,
) -> 'PublicKey':
```

Creates a new SSH Public key from a cryptography class

#### Arguments

- `key_class` *PubkeyClasses* - The cryptography class containing the public key
comment (Union[str, bytes], optional): Comment to add to the key. Defaults to None.
key_type (Union[str, bytes], optional): Manually specify the key type. Defaults to None.

#### Raises

- `_EX.InvalidKeyException` - The key you are trying to load is invalid

#### Returns

- `PublicKey` - Any of the PublicKey child classes

#### See also

- [PubkeyClasses](#pubkeyclasses)

### PublicKey.from_file

[[find in source code]](../../../src/sshkey_tools/keys.py#L183)

```python
@classmethod
def from_file(path: str) -> 'PublicKey':
```

Loads an SSH Public key from a file

#### Arguments

- `path` *str* - The path to the file

#### Returns

- `PublicKey` - Any of the PublicKey child classes

### PublicKey.from_string

[[find in source code]](../../../src/sshkey_tools/keys.py#L155)

```python
@classmethod
def from_string(data: Union[str, bytes]) -> 'PublicKey':
```

Loads an SSH public key from a string containing the data
in OpenSSH format (SubjectPublickeyInfo)

#### Arguments

data (Union[str, bytes]): The string or byte data containing the key

#### Returns

- `PublicKey` - Any of the PublicKey child classes

### PublicKey().get_fingerprint

[[find in source code]](../../../src/sshkey_tools/keys.py#L199)

```python
def get_fingerprint(
    hash_method: FingerprintHashes = FingerprintHashes.SHA256,
) -> str:
```

Generates a fingerprint of the public key

#### Arguments

- `hash_method` *FingerprintHashes, optional* - Type of hash. Defaults to SHA256.

#### Returns

- `str` - The hash of the public key

#### See also

- [FingerprintHashes](#fingerprinthashes)

### PublicKey().raw_bytes

[[find in source code]](../../../src/sshkey_tools/keys.py#L225)

```python
def raw_bytes() -> bytes:
```

Export the public key to a raw byte string

#### Returns

- `bytes` - The raw certificate bytes

### PublicKey().serialize

[[find in source code]](../../../src/sshkey_tools/keys.py#L214)

```python
def serialize() -> bytes:
```

Serialize the key for storage in file or string

#### Returns

- `bytes` - The serialized key in OpenSSH format

### PublicKey().to_file

[[find in source code]](../../../src/sshkey_tools/keys.py#L249)

```python
def to_file(path: str, encoding: str = 'utf-8') -> None:
```

Export the public key to a file

#### Arguments

- `path` *str* - The path of the file
- `encoding(str,` *optional)* - The encoding of the file. Defaults to 'utf-8'.

### PublicKey().to_string

[[find in source code]](../../../src/sshkey_tools/keys.py#L234)

```python
def to_string(encoding: str = 'utf-8') -> str:
```

Export the public key as a string

#### Returns

- `str` - The public key in OpenSSH format
- `encoding(str,` *optional)* - The encoding of the file. Defaults to 'utf-8'.

## RSAPrivateKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L449)

```python
class RSAPrivateKey(PrivateKey):
    def __init__(key: _RSA.RSAPrivateKey):
```

Class for holding RSA private keys

#### See also

- [PrivateKey](#privatekey)

### RSAPrivateKey.from_numbers

[[find in source code]](../../../src/sshkey_tools/keys.py#L462)

```python
@classmethod
def from_numbers(
    n: int,
    e: int,
    d: int,
    p: int = None,
    q: int = None,
    dmp1: int = None,
    dmq1: int = None,
    iqmp: int = None,
) -> 'RSAPrivateKey':
```

Load an RSA private key from numbers

#### Arguments

- `n` *int* - The public modulus (n)
- `e` *int* - The public exponent (e)
- `d` *int* - The private exponent (d)
- `p` *int, optional* - One of two primes (p) composing the public modulus.
                   Automatically generates if not provided.
- `q` *int, optional* - One of two primes (q) composing the public modulus.
                   Automatically generates if not provided
- `dmp1` *int, optional* - Chinese remainder theorem coefficient to speed up operations
                      Calculated as d mod (p-1)
                      Automatically generates if not provided
- `dmq1` *int, optional* - Chinese remainder theorem coefficient to speed up operations
                      Calculated as d mod(q-1)
                      Automatically generates if not provided
- `iqmp` *int, optional* - Chinese remainder theorem coefficient to speed up operations
                      Calculated as q^-1 mod p
                   Automatically generates if not provided

#### Returns

- `RSAPrivateKey` - An instance of RSAPrivateKey

### RSAPrivateKey.generate

[[find in source code]](../../../src/sshkey_tools/keys.py#L518)

```python
@classmethod
def generate(
    key_size: int = 4096,
    public_exponent: int = 65537,
) -> 'RSAPrivateKey':
```

Generates a new RSA private key

#### Arguments

- `key_size` *int, optional* - The number of bytes for the key. Defaults to 4096.
- `public_exponent` *int, optional* - The public exponent to use. Defaults to 65537.

#### Returns

- `RSAPrivateKey` - Instance of RSAPrivateKey

### RSAPrivateKey().sign

[[find in source code]](../../../src/sshkey_tools/keys.py#L541)

```python
def sign(data: bytes, hash_alg: RsaAlgs = RsaAlgs.SHA512) -> bytes:
```

Signs a block of data and returns the signature

#### Arguments

- `data` *bytes* - Block of byte data to sign
- `hash_alg` *RsaAlgs, optional* - Algorithm to use for hashing.
                              Defaults to SHA512.

#### Returns

- `bytes` - The signature bytes

#### See also

- [RsaAlgs](#rsaalgs)

## RSAPublicKey

[[find in source code]](../../../src/sshkey_tools/keys.py#L413)

```python
class RSAPublicKey(PublicKey):
    def __init__(
        key: _RSA.RSAPublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
        serialized: bytes = None,
    ):
```

Class for holding RSA public keys

#### See also

- [PublicKey](#publickey)

### RSAPublicKey.from_numbers

[[find in source code]](../../../src/sshkey_tools/keys.py#L432)

```python
@classmethod
def from_numbers(e: int, n: int) -> 'RSAPublicKey':
```

Loads an RSA Public Key from the public numbers e and n

#### Arguments

- `e` *int* - e-value
- `n` *int* - n-value

#### Returns

- `RSAPublicKey` - _description_

## RsaAlgs

[[find in source code]](../../../src/sshkey_tools/keys.py#L67)

```python
class RsaAlgs(Enum):
```

RSA Algorithms
