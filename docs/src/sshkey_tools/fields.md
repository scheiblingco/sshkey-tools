# Fields

> Auto-generated documentation for [src.sshkey_tools.fields](../../../src/sshkey_tools/fields.py) module.

Field types for SSH Certificates

- [Sshkey-tools](../../README.md#sshkey-tools-work-in-progress) / [Modules](../../MODULES.md#sshkey-tools-modules) / `Src` / [Sshkey Tools](index.md#sshkey-tools) / Fields
    - [BooleanField](#booleanfield)
        - [BooleanField.decode](#booleanfielddecode)
        - [BooleanField.encode](#booleanfieldencode)
        - [BooleanField().validate](#booleanfieldvalidate)
    - [CAPublicKeyField](#capublickeyfield)
        - [CAPublicKeyField.decode](#capublickeyfielddecode)
        - [CAPublicKeyField.from_object](#capublickeyfieldfrom_object)
        - [CAPublicKeyField().validate](#capublickeyfieldvalidate)
    - [CERT_TYPE](#cert_type)
    - [CertificateField](#certificatefield)
        - [CertificateField.decode](#certificatefielddecode)
        - [CertificateField.encode](#certificatefieldencode)
        - [CertificateField.from_decode](#certificatefieldfrom_decode)
        - [CertificateField().validate](#certificatefieldvalidate)
    - [CertificateTypeField](#certificatetypefield)
        - [CertificateTypeField().validate](#certificatetypefieldvalidate)
    - [CriticalOptionsField](#criticaloptionsfield)
        - [CriticalOptionsField().validate](#criticaloptionsfieldvalidate)
    - [DSAPubkeyField](#dsapubkeyfield)
        - [DSAPubkeyField.decode](#dsapubkeyfielddecode)
        - [DSAPubkeyField().validate](#dsapubkeyfieldvalidate)
    - [DSASignatureField](#dsasignaturefield)
        - [DSASignatureField.decode](#dsasignaturefielddecode)
        - [DSASignatureField.encode](#dsasignaturefieldencode)
        - [DSASignatureField.from_decode](#dsasignaturefieldfrom_decode)
        - [DSASignatureField().sign](#dsasignaturefieldsign)
    - [DateTimeField](#datetimefield)
        - [DateTimeField.decode](#datetimefielddecode)
        - [DateTimeField.encode](#datetimefieldencode)
        - [DateTimeField().validate](#datetimefieldvalidate)
    - [ECDSAPubkeyField](#ecdsapubkeyfield)
        - [ECDSAPubkeyField.decode](#ecdsapubkeyfielddecode)
        - [ECDSAPubkeyField().validate](#ecdsapubkeyfieldvalidate)
    - [ECDSASignatureField](#ecdsasignaturefield)
        - [ECDSASignatureField.decode](#ecdsasignaturefielddecode)
        - [ECDSASignatureField.encode](#ecdsasignaturefieldencode)
        - [ECDSASignatureField.from_decode](#ecdsasignaturefieldfrom_decode)
        - [ECDSASignatureField().sign](#ecdsasignaturefieldsign)
    - [ED25519PubkeyField](#ed25519pubkeyfield)
        - [ED25519PubkeyField.decode](#ed25519pubkeyfielddecode)
        - [ED25519PubkeyField().validate](#ed25519pubkeyfieldvalidate)
    - [ED25519SignatureField](#ed25519signaturefield)
        - [ED25519SignatureField.decode](#ed25519signaturefielddecode)
        - [ED25519SignatureField.encode](#ed25519signaturefieldencode)
        - [ED25519SignatureField.from_decode](#ed25519signaturefieldfrom_decode)
        - [ED25519SignatureField().sign](#ed25519signaturefieldsign)
    - [ExtensionsField](#extensionsfield)
        - [ExtensionsField().validate](#extensionsfieldvalidate)
    - [Integer32Field](#integer32field)
        - [Integer32Field.decode](#integer32fielddecode)
        - [Integer32Field.encode](#integer32fieldencode)
        - [Integer32Field().validate](#integer32fieldvalidate)
    - [Integer64Field](#integer64field)
        - [Integer64Field.decode](#integer64fielddecode)
        - [Integer64Field.encode](#integer64fieldencode)
        - [Integer64Field().validate](#integer64fieldvalidate)
    - [KeyIDField](#keyidfield)
        - [KeyIDField().validate](#keyidfieldvalidate)
    - [MpIntegerField](#mpintegerfield)
        - [MpIntegerField.decode](#mpintegerfielddecode)
        - [MpIntegerField.encode](#mpintegerfieldencode)
        - [MpIntegerField().validate](#mpintegerfieldvalidate)
    - [NonceField](#noncefield)
        - [NonceField().validate](#noncefieldvalidate)
    - [PrincipalsField](#principalsfield)
    - [PubkeyTypeField](#pubkeytypefield)
        - [PubkeyTypeField().validate](#pubkeytypefieldvalidate)
    - [PublicKeyField](#publickeyfield)
        - [PublicKeyField.encode](#publickeyfieldencode)
        - [PublicKeyField.from_object](#publickeyfieldfrom_object)
    - [RSAPubkeyField](#rsapubkeyfield)
        - [RSAPubkeyField.decode](#rsapubkeyfielddecode)
        - [RSAPubkeyField().validate](#rsapubkeyfieldvalidate)
    - [RSASignatureField](#rsasignaturefield)
        - [RSASignatureField.decode](#rsasignaturefielddecode)
        - [RSASignatureField.encode](#rsasignaturefieldencode)
        - [RSASignatureField.from_decode](#rsasignaturefieldfrom_decode)
        - [RSASignatureField().sign](#rsasignaturefieldsign)
    - [ReservedField](#reservedfield)
        - [ReservedField().validate](#reservedfieldvalidate)
    - [SeparatedListField](#separatedlistfield)
        - [SeparatedListField.decode](#separatedlistfielddecode)
        - [SeparatedListField.encode](#separatedlistfieldencode)
        - [SeparatedListField().validate](#separatedlistfieldvalidate)
    - [SerialField](#serialfield)
    - [SignatureField](#signaturefield)
        - [SignatureField().can_sign](#signaturefieldcan_sign)
        - [SignatureField.from_decode](#signaturefieldfrom_decode)
        - [SignatureField.from_object](#signaturefieldfrom_object)
        - [SignatureField().sign](#signaturefieldsign)
    - [StandardListField](#standardlistfield)
        - [StandardListField.decode](#standardlistfielddecode)
        - [StandardListField.encode](#standardlistfieldencode)
        - [StandardListField().validate](#standardlistfieldvalidate)
    - [StringField](#stringfield)
        - [StringField.decode](#stringfielddecode)
        - [StringField.encode](#stringfieldencode)
        - [StringField().validate](#stringfieldvalidate)
    - [ValidityEndField](#validityendfield)
    - [ValidityStartField](#validitystartfield)

## BooleanField

[[find in source code]](../../../src/sshkey_tools/fields.py#L121)

```python
class BooleanField(CertificateField):
```

Field representing a boolean value (True/False)

#### See also

- [CertificateField](#certificatefield)

### BooleanField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L138)

```python
@staticmethod
def decode(data: bytes) -> Tuple[bool, bytes]:
```

Decodes a boolean from a bytestring

#### Arguments

- `data` *bytes* - The byte string starting with an encoded boolean

### BooleanField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L125)

```python
@staticmethod
def encode(value: bool) -> bytes:
```

Encodes a boolean value to a byte string

#### Arguments

- `value` *bool* - Boolean to encode

#### Returns

- `bytes` - Packed byte representing the boolean

### BooleanField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L148)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## CAPublicKeyField

[[find in source code]](../../../src/sshkey_tools/fields.py#L988)

```python
class CAPublicKeyField(StringField):
    def __init__(value: PublicKey):
```

Contains the public key of the certificate authority
that is used to sign the certificate.

#### See also

- [StringField](#stringfield)

### CAPublicKeyField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1027)

```python
@staticmethod
def decode(data) -> Tuple[PublicKey, bytes]:
```

Decode the certificate field from a byte string
starting with the encoded public key

#### Arguments

- `data` *bytes* - The byte string starting with the encoded key

#### Returns

- `Tuple[PublicKey,` *bytes]* - The PublicKey field and remainder of the data

### CAPublicKeyField.from_object

[[find in source code]](../../../src/sshkey_tools/fields.py#L1051)

```python
@classmethod
def from_object(public_key: PublicKey) -> 'CAPublicKeyField':
```

Creates a new CAPublicKeyField from a PublicKey object

### CAPublicKeyField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L1011)

```python
def validate() -> Union[bool, Exception]:
```

Validates the contents of the field

## CERT_TYPE

[[find in source code]](../../../src/sshkey_tools/fields.py#L66)

```python
class CERT_TYPE(Enum):
```

Certificate types, User certificate/Host certificate

## CertificateField

[[find in source code]](../../../src/sshkey_tools/fields.py#L73)

```python
class CertificateField():
    def __init__(value, name=None):
```

The base class for certificate fields

### CertificateField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L94)

```python
@staticmethod
def decode(data: bytes) -> tuple:
```

Returns the decoded value of the field

### CertificateField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L88)

```python
@staticmethod
def encode(value) -> bytes:
```

Returns the encoded value of the field

### CertificateField.from_decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L110)

```python
@classmethod
def from_decode(data: bytes) -> Tuple['CertificateField', bytes]:
```

Creates a field class based on encoded bytes

#### Returns

- `tuple` - CertificateField, remaining bytes

### CertificateField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L104)

```python
def validate() -> Union[bool, Exception]:
```

Validates the field

## CertificateTypeField

[[find in source code]](../../../src/sshkey_tools/fields.py#L769)

```python
class CertificateTypeField(Integer32Field):
    def __init__(value: Union[CERT_TYPE, int]):
```

Contains the certificate type
User certificate: CERT_TYPE.USER/1
Host certificate: CERT_TYPE.HOST/2

#### See also

- [CERT_TYPE](#cert_type)
- [Integer32Field](#integer32field)

### CertificateTypeField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L781)

```python
def validate() -> Union[bool, Exception]:
```

Validates that the field contains a valid type

## CriticalOptionsField

[[find in source code]](../../../src/sshkey_tools/fields.py#L848)

```python
class CriticalOptionsField(SeparatedListField):
    def __init__(value: Union[list, tuple]):
```

Contains the critical options part of the certificate (optional).
This should be a list of strings with one of the following

options:
    force_command=<command>
        Limits the connecting user to a specific command,
        e.g. sftp-internal
    source_address=<ip_address>
        Limits the user to connect only from a certain
        ip, subnet or host
    verify_required=<true|false>
        If set to true, the user must verify their identity
        if using a hardware token

Additionally, the following flags are also supported (no value):
flags:
    no-touch-required
        The user doesn't need to touch the
        physical key to authenticate.

permit-X11-forwarding
    Permits the user to use X11 Forwarding

permit-agent-forwarding
    Permits the user to use agent forwarding

permit-port-forwarding
    Permits the user to forward ports

permit-pty
    Permits the user to use a pseudo-terminal

permit-user-rc
    Permits the user to use the user rc file

#### See also

- [SeparatedListField](#separatedlistfield)

### CriticalOptionsField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L892)

```python
def validate() -> Union[bool, Exception]:
```

Validate that the field contains a valid list of options

## DSAPubkeyField

[[find in source code]](../../../src/sshkey_tools/fields.py#L645)

```python
class DSAPubkeyField(PublicKeyField):
```

Holds the DSA Public Key for DSA Certificates

#### See also

- [PublicKeyField](#publickeyfield)

### DSAPubkeyField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L650)

```python
@staticmethod
def decode(data: bytes) -> Tuple[DSAPublicKey, bytes]:
```

Decode the certificate field from a byte string
starting with the encoded public key

#### Arguments

- `data` *bytes* - The byte string starting with the encoded key

#### Returns

- `Tuple[RSAPublicKey,` *bytes]* - The PublicKey field and remainder of the data

### DSAPubkeyField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L671)

```python
def validate() -> Union[bool, Exception]:
```

Validates that the field data is a valid DSA Public Key

## DSASignatureField

[[find in source code]](../../../src/sshkey_tools/fields.py#L1250)

```python
class DSASignatureField(SignatureField):
    def __init__(
        private_key: DSAPrivateKey = None,
        signature: bytes = None,
    ) -> None:
```

Creates and contains the DSA signature from an DSA Private Key

#### See also

- [SignatureField](#signaturefield)

### DSASignatureField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1283)

```python
@staticmethod
def decode(data: bytes) -> Tuple[bytes, bytes]:
```

Decodes a bytestring containing a signature

#### Arguments

- `data` *bytes* - The bytestring starting with the Signature

#### Returns

Tuple[ bytes, bytes ]: signature, remainder of the data

### DSASignatureField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1261)

```python
@staticmethod
def encode(signature: bytes):
```

Encodes the signature to a byte string

#### Arguments

- `signature` *bytes* - The signature bytes to encode

#### Returns

- `bytes` - The encoded byte string

### DSASignatureField.from_decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1306)

```python
@classmethod
def from_decode(data: bytes) -> Tuple['DSASignatureField', bytes]:
```

Creates a signature field class from the encoded signature

#### Arguments

- `data` *bytes* - The bytestring starting with the Signature

#### Returns

Tuple[ DSASignatureField, bytes ]: signature, remainder of the data

### DSASignatureField().sign

[[find in source code]](../../../src/sshkey_tools/fields.py#L1324)

```python
def sign(data: bytes) -> None:
```

Signs the provided data with the provided private key

#### Arguments

- `data` *bytes* - The data to be signed

## DateTimeField

[[find in source code]](../../../src/sshkey_tools/fields.py#L305)

```python
class DateTimeField(Integer64Field):
```

Certificate field representing a datetime value.
The value is saved as a 64-bit integer (unix timestamp)

#### See also

- [Integer64Field](#integer64field)

### DateTimeField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L314)

```python
@staticmethod
def decode(data: bytes) -> datetime:
```

### DateTimeField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L310)

```python
@staticmethod
def encode(value: datetime) -> bytes:
```

### DateTimeField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L322)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## ECDSAPubkeyField

[[find in source code]](../../../src/sshkey_tools/fields.py#L682)

```python
class ECDSAPubkeyField(PublicKeyField):
```

Holds the ECDSA Public Key for ECDSA Certificates

#### See also

- [PublicKeyField](#publickeyfield)

### ECDSAPubkeyField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L687)

```python
@staticmethod
def decode(data: bytes) -> Tuple[ECDSAPublicKey, bytes]:
```

Decode the certificate field from a byte string
starting with the encoded public key

#### Arguments

- `data` *bytes* - The byte string starting with the encoded key

#### Returns

- `Tuple[ECPublicKey,` *bytes]* - The PublicKey field and remainder of the data

### ECDSAPubkeyField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L713)

```python
def validate() -> Union[bool, Exception]:
```

Validates that the field data is a valid ECDSA Public Key

## ECDSASignatureField

[[find in source code]](../../../src/sshkey_tools/fields.py#L1336)

```python
class ECDSASignatureField(SignatureField):
    def __init__(
        private_key: ECDSAPrivateKey = None,
        signature: bytes = None,
        curve_name: str = None,
    ) -> None:
```

Creates and contains the ECDSA signature from an ECDSA Private Key

#### See also

- [SignatureField](#signaturefield)

### ECDSASignatureField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1380)

```python
@staticmethod
def decode(data: bytes) -> Tuple[Tuple[bytes, bytes], bytes]:
```

Decodes a bytestring containing a signature

#### Arguments

- `data` *bytes* - The bytestring starting with the Signature

#### Returns

Tuple[ Tuple[ bytes, bytes ], bytes]: (curve, signature), remainder of the data

### ECDSASignatureField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1354)

```python
@staticmethod
def encode(signature: bytes, curve_name: str = None) -> bytes:
```

Encodes the signature to a byte string

#### Arguments

- `signature` *bytes* - The signature bytes to encode
- `curve_name` *str* - The name of the curve used for the signature
                  private key

#### Returns

- `bytes` - The encoded byte string

### ECDSASignatureField.from_decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1403)

```python
@classmethod
def from_decode(data: bytes) -> Tuple['ECDSASignatureField', bytes]:
```

Creates a signature field class from the encoded signature

#### Arguments

- `data` *bytes* - The bytestring starting with the Signature

#### Returns

Tuple[ ECDSASignatureField , bytes ]: signature, remainder of the data

### ECDSASignatureField().sign

[[find in source code]](../../../src/sshkey_tools/fields.py#L1422)

```python
def sign(data: bytes) -> None:
```

Signs the provided data with the provided private key

#### Arguments

- `data` *bytes* - The data to be signed

## ED25519PubkeyField

[[find in source code]](../../../src/sshkey_tools/fields.py#L724)

```python
class ED25519PubkeyField(PublicKeyField):
```

Holds the ED25519 Public Key for ED25519 Certificates

#### See also

- [PublicKeyField](#publickeyfield)

### ED25519PubkeyField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L729)

```python
@staticmethod
def decode(data: bytes) -> Tuple[ED25519PublicKey, bytes]:
```

Decode the certificate field from a byte string
starting with the encoded public key

#### Arguments

- `data` *bytes* - The byte string starting with the encoded key

#### Returns

- `Tuple[ED25519PublicKey,` *bytes]* - The PublicKey field and remainder of the data

### ED25519PubkeyField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L747)

```python
def validate() -> Union[bool, Exception]:
```

Validates that the field data is a valid ED25519 Public Key

## ED25519SignatureField

[[find in source code]](../../../src/sshkey_tools/fields.py#L1440)

```python
class ED25519SignatureField(SignatureField):
    def __init__(
        private_key: ED25519PrivateKey = None,
        signature: bytes = None,
    ) -> None:
```

Creates and contains the ED25519 signature from an ED25519 Private Key

#### See also

- [SignatureField](#signaturefield)

### ED25519SignatureField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1468)

```python
@staticmethod
def decode(data: bytes) -> Tuple[bytes, bytes]:
```

Decodes a bytestring containing a signature

#### Arguments

- `data` *bytes* - The bytestring starting with the Signature

#### Returns

Tuple[ bytes, bytes ]: signature, remainder of the data

### ED25519SignatureField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1451)

```python
@staticmethod
def encode(signature: bytes) -> None:
```

Encodes the signature to a byte string

#### Arguments

- `signature` *bytes* - The signature bytes to encode

#### Returns

- `bytes` - The encoded byte string

### ED25519SignatureField.from_decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1487)

```python
@classmethod
def from_decode(data: bytes) -> Tuple['ED25519SignatureField', bytes]:
```

Creates a signature field class from the encoded signature

#### Arguments

- `data` *bytes* - The bytestring starting with the Signature

#### Returns

Tuple[ ED25519SignatureField , bytes ]: signature, remainder of the data

### ED25519SignatureField().sign

[[find in source code]](../../../src/sshkey_tools/fields.py#L1505)

```python
def sign(data: bytes) -> None:
```

Signs the provided data with the provided private key

#### Arguments

- `data` *bytes* - The data to be signed
- `hash_alg` *RsaAlgs, optional* - The RSA algorithm to use for hashing.
                               Defaults to RsaAlgs.SHA256.

## ExtensionsField

[[find in source code]](../../../src/sshkey_tools/fields.py#L911)

```python
class ExtensionsField(SeparatedListField):
    def __init__(value: Union[list, tuple]):
```

Contains a list of extensions for the certificate,
set to give the user limitations and/or additional
privileges on the host.

flags:
    no-touch-required
        The user doesn't need to touch the
        physical key to authenticate.

permit-X11-forwarding
    Permits the user to use X11 Forwarding

permit-agent-forwarding
    Permits the user to use agent forwarding

permit-port-forwarding
    Permits the user to forward ports

permit-pty
    Permits the user to use a pseudo-terminal

permit-user-rc
    Permits the user to use the user rc file

#### See also

- [SeparatedListField](#separatedlistfield)

### ExtensionsField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L944)

```python
def validate() -> Union[bool, Exception]:
```

Validates that the options provided are valid

## Integer32Field

[[find in source code]](../../../src/sshkey_tools/fields.py#L211)

```python
class Integer32Field(CertificateField):
```

Certificate field representing a 32-bit integer

#### See also

- [CertificateField](#certificatefield)

### Integer32Field.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L230)

```python
@staticmethod
def decode(data: bytes) -> Tuple[int, bytes]:
```

Decodes a 32-bit integer from a block of bytes

#### Arguments

- `data` *bytes* - Block of bytes containing an integer

#### Returns

- `tuple` - Tuple with integer and remainder of data

### Integer32Field.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L215)

```python
@staticmethod
def encode(value: int) -> bytes:
```

Encodes a 32-bit integer value to a packed byte string

#### Arguments

- `source_int` *int* - Integer to be packed

#### Returns

- `bytes` - Packed byte string containing integer

### Integer32Field().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L242)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## Integer64Field

[[find in source code]](../../../src/sshkey_tools/fields.py#L258)

```python
class Integer64Field(CertificateField):
```

Certificate field representing a 64-bit integer

#### See also

- [CertificateField](#certificatefield)

### Integer64Field.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L277)

```python
@staticmethod
def decode(data: bytes) -> Tuple[int, bytes]:
```

Decodes a 64-bit integer from a block of bytes

#### Arguments

- `data` *bytes* - Block of bytes containing an integer

#### Returns

- `tuple` - Tuple with integer and remainder of data

### Integer64Field.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L262)

```python
@staticmethod
def encode(value: int) -> bytes:
```

Encodes a 64-bit integer value to a packed byte string

#### Arguments

- `source_int` *int* - Integer to be packed

#### Returns

- `bytes` - Packed byte string containing integer

### Integer64Field().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L289)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## KeyIDField

[[find in source code]](../../../src/sshkey_tools/fields.py#L793)

```python
class KeyIDField(StringField):
    def __init__(value: str):
```

Contains the key identifier (subject) of the certificate,
alphanumeric string

#### See also

- [StringField](#stringfield)

### KeyIDField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L804)

```python
def validate() -> Union[bool, Exception]:
```

Validates that the field is set and not empty

## MpIntegerField

[[find in source code]](../../../src/sshkey_tools/fields.py#L333)

```python
class MpIntegerField(StringField):
```

Certificate field representing a multiple precision integer,
an integer too large to fit in 64 bits.

#### See also

- [StringField](#stringfield)

### MpIntegerField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L355)

```python
@staticmethod
def decode(data: bytes) -> Tuple[int, bytes]:
```

Decodes a multiprecision integer (integer larger than 64bit)

#### Arguments

- `data` *bytes* - Block of bytes containing a long (mp) integer

#### Returns

- `tuple` - Tuple with integer and remainder of data

### MpIntegerField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L338)

```python
@staticmethod
def encode(value: int) -> bytes:
```

Encodes a multiprecision integer (integer larger than 64bit)
into a packed byte string

#### Arguments

- `value` *int* - Large integer

#### Returns

- `bytes` - Packed byte string containing integer

### MpIntegerField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L368)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## NonceField

[[find in source code]](../../../src/sshkey_tools/fields.py#L526)

```python
class NonceField(StringField):
    def __init__(value: str = None):
```

Contains the nonce for the certificate, randomly generated
this protects the integrity of the private key, especially
for ecdsa.

#### See also

- [StringField](#stringfield)

### NonceField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L538)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## PrincipalsField

[[find in source code]](../../../src/sshkey_tools/fields.py#L815)

```python
class PrincipalsField(StandardListField):
    def __init__(value: Union[list, tuple]):
```

Contains a list of principals for the certificate,
e.g. SERVERHOSTNAME01 or all-web-servers

#### See also

- [StandardListField](#standardlistfield)

## PubkeyTypeField

[[find in source code]](../../../src/sshkey_tools/fields.py#L496)

```python
class PubkeyTypeField(StringField):
    def __init__(value: str):
```

Contains the certificate type, which is based on the
public key type the certificate is created for, e.g.
'ssh-ed25519-cert-v01@openssh.com' for an ED25519 key

#### See also

- [StringField](#stringfield)

### PubkeyTypeField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L508)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## PublicKeyField

[[find in source code]](../../../src/sshkey_tools/fields.py#L550)

```python
class PublicKeyField(CertificateField):
    def __init__(value: PublicKey):
```

Contains the subject (User or Host) public key for whom/which
the certificate is created.

#### See also

- [CertificateField](#certificatefield)

### PublicKeyField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L567)

```python
@staticmethod
def encode(value: RSAPublicKey) -> bytes:
```

Encode the certificate field to a byte string

#### Arguments

- `value` *RSAPublicKey* - The public key to encode

#### Returns

- `bytes` - A byte string with the encoded public key

### PublicKeyField.from_object

[[find in source code]](../../../src/sshkey_tools/fields.py#L583)

```python
@staticmethod
def from_object(public_key: PublicKey):
```

Loads the public key from a sshkey_tools.keys.PublicKey
class or childclass

#### Arguments

- `public_key` *PublicKey* - The public key for which to
                        create the certificate

#### Raises

- `_EX.InvalidKeyException` - Invalid public key

#### Returns

- `PublicKeyField` - A child class of PublicKeyField specific
                to the chosen public key

## RSAPubkeyField

[[find in source code]](../../../src/sshkey_tools/fields.py#L609)

```python
class RSAPubkeyField(PublicKeyField):
```

Holds the RSA Public Key for RSA Certificates

#### See also

- [PublicKeyField](#publickeyfield)

### RSAPubkeyField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L614)

```python
@staticmethod
def decode(data: bytes) -> Tuple[RSAPublicKey, bytes]:
```

Decode the certificate field from a byte string
starting with the encoded public key

#### Arguments

- `data` *bytes* - The byte string starting with the encoded key

#### Returns

- `Tuple[RSAPublicKey,` *bytes]* - The PublicKey field and remainder of the data

### RSAPubkeyField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L634)

```python
def validate() -> Union[bool, Exception]:
```

Validates that the field data is a valid RSA Public Key

## RSASignatureField

[[find in source code]](../../../src/sshkey_tools/fields.py#L1144)

```python
class RSASignatureField(SignatureField):
    def __init__(
        private_key: RSAPrivateKey = None,
        hash_alg: RsaAlgs = RsaAlgs.SHA512,
        signature: bytes = None,
    ):
```

Creates and contains the RSA signature from an RSA Private Key

#### See also

- [SignatureField](#signaturefield)

### RSASignatureField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1176)

```python
@staticmethod
def decode(data: bytes) -> Tuple[Tuple[bytes, bytes], bytes]:
```

Decodes a bytestring containing a signature

#### Arguments

- `data` *bytes* - The bytestring starting with the RSA Signature

#### Returns

Tuple[ Tuple[ bytes, bytes ], bytes ]: (signature_type, signature), remainder of data

### RSASignatureField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1157)

```python
@staticmethod
def encode(signature: bytes, hash_alg: RsaAlgs = RsaAlgs.SHA256) -> bytes:
```

Encodes the signature to a byte string

#### Arguments

- `signature` *bytes* - The signature bytes to encode
- `hash_alg` *RsaAlgs, optional* - The hash algorithm used for the signature.
                                Defaults to RsaAlgs.SHA256.

#### Returns

- `bytes` - The encoded byte string

### RSASignatureField.from_decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1200)

```python
@classmethod
def from_decode(data: bytes) -> Tuple['RSASignatureField', bytes]:
```

Generates an RSASignatureField class from the encoded signature

#### Arguments

- `data` *bytes* - The bytestring containing the encoded signature

#### Raises

- `_EX.InvalidDataException` - Invalid data

#### Returns

- `Tuple[RSASignatureField,` *bytes]* - RSA Signature field and remainder of data

### RSASignatureField().sign

[[find in source code]](../../../src/sshkey_tools/fields.py#L1222)

```python
def sign(data: bytes, hash_alg: RsaAlgs = RsaAlgs.SHA256) -> None:
```

Signs the provided data with the provided private key

#### Arguments

- `data` *bytes* - The data to be signed
- `hash_alg` *RsaAlgs, optional* - The RSA algorithm to use for hashing.
                               Defaults to RsaAlgs.SHA256.

## ReservedField

[[find in source code]](../../../src/sshkey_tools/fields.py#L966)

```python
class ReservedField(StringField):
    def __init__(value: str = ''):
```

This field is reserved for future use, and
doesn't contain any actual data, just an empty string.

#### See also

- [StringField](#stringfield)

### ReservedField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L977)

```python
def validate() -> Union[bool, Exception]:
```

Validate that the field only contains an empty string

## SeparatedListField

[[find in source code]](../../../src/sshkey_tools/fields.py#L434)

```python
class SeparatedListField(CertificateField):
```

Certificate field representing a list or integer in python,
separated in byte-form by null-bytes.

#### See also

- [CertificateField](#certificatefield)

### SeparatedListField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L465)

```python
@staticmethod
def decode(data: bytes) -> Tuple[list, bytes]:
```

Decodes a list of strings from a block of bytes

#### Arguments

- `data` *bytes* - The block of bytes containing a list of strings

#### Returns

- `tuple` - _description_

### SeparatedListField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L440)

```python
@staticmethod
def encode(value: Union[list, tuple]) -> bytes:
```

Encodes a list or tuple to a byte string separated by a null byte

#### Arguments

- `source_list` *list* - list of strings

#### Returns

- `bytes` - Packed byte string containing the source data

### SeparatedListField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L485)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## SerialField

[[find in source code]](../../../src/sshkey_tools/fields.py#L758)

```python
class SerialField(Integer64Field):
    def __init__(value: int):
```

Contains the numeric serial number of the certificate,
maximum is (2**64)-1

#### See also

- [Integer64Field](#integer64field)

## SignatureField

[[find in source code]](../../../src/sshkey_tools/fields.py#L1061)

```python
class SignatureField(CertificateField):
    def __init__(private_key: PrivateKey = None, signature: bytes = None):
```

Creates and contains the signature of the certificate

#### See also

- [CertificateField](#certificatefield)

### SignatureField().can_sign

[[find in source code]](../../../src/sshkey_tools/fields.py#L1127)

```python
def can_sign():
```

Determines if a signature can be generated from
this private key

### SignatureField.from_decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L1100)

```python
@staticmethod
def from_decode(data: bytes) -> Tuple['SignatureField', bytes]:
```

Generates a SignatureField child class from the encoded signature

#### Arguments

- `data` *bytes* - The bytestring containing the encoded signature

#### Raises

- `_EX.InvalidDataException` - Invalid data

#### Returns

- `SignatureField` - child of SignatureField

### SignatureField.from_object

[[find in source code]](../../../src/sshkey_tools/fields.py#L1076)

```python
@staticmethod
def from_object(private_key: PrivateKey):
```

Load a private key from a PrivateKey object

#### Arguments

- `private_key` *PrivateKey* - Private key to use for signing

#### Raises

- `_EX.InvalidKeyException` - Invalid private key

#### Returns

- `SignatureField` - SignatureField child class

### SignatureField().sign

[[find in source code]](../../../src/sshkey_tools/fields.py#L1134)

```python
def sign(data: bytes) -> None:
```

Placeholder signing function

## StandardListField

[[find in source code]](../../../src/sshkey_tools/fields.py#L379)

```python
class StandardListField(CertificateField):
```

Certificate field representing a list or tuple of strings

#### See also

- [CertificateField](#certificatefield)

### StandardListField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L405)

```python
@staticmethod
def decode(data: bytes) -> Tuple[list, bytes]:
```

Decodes a list of strings from a block of bytes

#### Arguments

- `data` *bytes* - The block of bytes containing a list of strings

#### Returns

- `tuple` - _description_

### StandardListField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L383)

```python
@staticmethod
def encode(value: Union[list, tuple]) -> bytes:
```

Encodes a list or tuple to a byte string

#### Arguments

- `source_list` *list* - list of strings
- `null_separator` *bool, optional* - Insert blank string string between items. Default None

#### Returns

- `bytes` - Packed byte string containing the source data

### StandardListField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L423)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## StringField

[[find in source code]](../../../src/sshkey_tools/fields.py#L159)

```python
class StringField(CertificateField):
```

Field representing a string value

#### See also

- [CertificateField](#certificatefield)

### StringField.decode

[[find in source code]](../../../src/sshkey_tools/fields.py#L183)

```python
@staticmethod
def decode(data: bytes) -> Tuple[str, bytes]:
```

Unpacks the next string from a packed byte string

#### Arguments

- `data` *bytes* - The packed byte string to unpack

#### Returns

- `tuple(str,` *bytes)* - The next string from the packed byte
                      string and remainder of the data

### StringField.encode

[[find in source code]](../../../src/sshkey_tools/fields.py#L163)

```python
@staticmethod
def encode(value: Union[str, bytes], encoding: str = 'utf-8') -> bytes:
```

Encodes a string or bytestring into a packed byte string

#### Arguments

value (Union[str, bytes]): The string/bytestring to encode
- `encoding` *str* - The encoding to user for the string

#### Returns

- `bytes` - Packed byte string containing the source data

### StringField().validate

[[find in source code]](../../../src/sshkey_tools/fields.py#L198)

```python
def validate() -> Union[bool, Exception]:
```

Validate the field data

## ValidityEndField

[[find in source code]](../../../src/sshkey_tools/fields.py#L837)

```python
class ValidityEndField(DateTimeField):
    def __init__(value: datetime):
```

Contains the end of the validity period for the certificate,
represented by a datetime object

#### See also

- [DateTimeField](#datetimefield)

## ValidityStartField

[[find in source code]](../../../src/sshkey_tools/fields.py#L826)

```python
class ValidityStartField(DateTimeField):
    def __init__(value: datetime):
```

Contains the start of the validity period for the certificate,
represented by a datetime object

#### See also

- [DateTimeField](#datetimefield)
