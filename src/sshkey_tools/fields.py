"""
Field types for SSH Certificates
"""
# pylint: disable=invalid-name,too-many-lines
from enum import Enum
from typing import Union, Tuple
from datetime import datetime
from struct import pack, unpack
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature
)
from . import exceptions as _EX
from .keys import (
    RsaAlgs,
    PrivateKey,
    PublicKey,
    RSAPublicKey,
    RSAPrivateKey,
    DSAPublicKey,
    DSAPrivateKey,
    ECDSAPublicKey,
    ECDSAPrivateKey,
    ED25519PublicKey,
    ED25519PrivateKey
)

from .utils import (
    long_to_bytes,
    bytes_to_long,
    generate_secure_nonce
)


MAX_INT32 = 2**32
MAX_INT64 = 2**64

ECDSA_CURVE_MAP = {
    'secp256r1': 'nistp256',
    'secp384r1': 'nistp384',
    'secp521r1': 'nistp521'
}

SUBJECT_PUBKEY_MAP = {
    RSAPublicKey: 'RSAPubkeyField',
    DSAPublicKey: 'DSAPubkeyField',
    ECDSAPublicKey: 'ECDSAPubkeyField',
    ED25519PublicKey: 'ED25519PubkeyField'
}

CA_SIGNATURE_MAP = {
    RSAPrivateKey: 'RSASignatureField',
    DSAPrivateKey: 'DSASignatureField',
    ECDSAPrivateKey: 'ECDSASignatureField',
    ED25519PrivateKey: 'ED25519SignatureField'
}

SIGNATURE_TYPE_MAP = {
    b'rsa': 'RSASignatureField',
    b'dss': 'DSASignatureField',
    b'ecdsa': 'ECDSASignatureField',
    b'ed25519': 'ED25519SignatureField'
}

class CERT_TYPE(Enum):
    """
    Certificate types, User certificate/Host certificate
    """
    USER = 1
    HOST = 2

class CertificateField:
    """
    The base class for certificate fields
    """
    is_set = None

    def __init__(self, value, name = None):
        self.name = name
        self.value = value
        self.exception = None
        self.is_set = True

    def __str__(self):
        return f"{self.name}: {self.value}"

    @staticmethod
    def encode(value) -> bytes:
        """
        Returns the encoded value of the field
        """

    @staticmethod
    def decode(data: bytes) -> tuple:
        """
        Returns the decoded value of the field
        """

    def __bytes__(self) -> bytes:
        return self.encode(self.value)

    # pylint: disable=no-self-use
    def validate(self) -> Union[bool, Exception]:
        """
        Validates the field
        """
        return True

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['CertificateField', bytes]:
        """
        Creates a field class based on encoded bytes

        Returns:
            tuple: CertificateField, remaining bytes
        """
        value, data = cls.decode(data)
        return cls(value), data

class BooleanField(CertificateField):
    """
    Field representing a boolean value (True/False)
    """
    @staticmethod
    def encode(value: bool) -> bytes:
        """
        Encodes a boolean value to a byte string

        Args:
            value (bool): Boolean to encode

        Returns:
            bytes: Packed byte representing the boolean
        """
        return pack('B', 1 if value else 0)

    @staticmethod
    def decode(data: bytes) -> Tuple[bool, bytes]:
        """
        Decodes a boolean from a bytestring

        Args:
            data (bytes): The byte string starting with an encoded boolean
        """
        return bool(unpack('B', data[:1])[0]), data[1:]

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if self.value not in [True, False]:
            return _EX.InvalidFieldDataException(
                f"Passed value type ({type(self.value)}) is not a boolean"
            )

        return True

class StringField(CertificateField):
    """
    Field representing a string value
    """
    @staticmethod
    def encode(value: Union[str, bytes], encoding: str = 'utf-8') -> bytes:
        """
        Encodes a string or bytestring into a packed byte string

        Args:
            value (Union[str, bytes]): The string/bytestring to encode
            encoding (str): The encoding to user for the string

        Returns:
            bytes: Packed byte string containing the source data
        """
        if isinstance(value, str):
            value = value.encode(encoding)

        if isinstance(value, bytes):
            return pack('>I', len(value)) + value

        raise _EX.InvalidDataException(f"Expected unicode or bytes, got {type(value).__name__}.")

    @staticmethod
    def decode(data: bytes) -> Tuple[str, bytes]:
        """
        Unpacks the next string from a packed byte string

        Args:
            data (bytes): The packed byte string to unpack

        Returns:
            tuple(str, bytes):    The next string from the packed byte
                                  string and remainder of the data
        """
        length = unpack('>I', data[:4])[0] + 4
        return data[4:length], data[length:]

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if not isinstance(self.value, Union[str, bytes]):
            return _EX.InvalidFieldDataException(
                f"Passed value type ({type(self.value)}) is not a string or bytestring"
            )

        return True



class Integer32Field(CertificateField):
    """
    Certificate field representing a 32-bit integer
    """
    @staticmethod
    def encode(value: int) -> bytes:
        """Encodes a 32-bit integer value to a packed byte string

        Args:
            source_int (int): Integer to be packed

        Returns:
            bytes: Packed byte string containing integer
        """
        if not isinstance(value, int):
            raise _EX.InvalidDataException(f"Expected integer, got {type(value).__name__}.")

        return pack('>I', value)

    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a 32-bit integer from a block of bytes

        Args:
            data (bytes): Block of bytes containing an integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        return int(unpack('>I', data[:4])[0]), data[4:]

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if not isinstance(self.value, int):
            return _EX.InvalidFieldDataException(
                f"Passed value type ({type(self.value)}) is not an integer"
            )

        if self.value > MAX_INT32:
            return _EX.IntegerOverflowException(
                f"Passed value {self.value} is too large for a 32-bit integer"
            )

        return True

class Integer64Field(CertificateField):
    """
    Certificate field representing a 64-bit integer
    """
    @staticmethod
    def encode(value: int) -> bytes:
        """Encodes a 64-bit integer value to a packed byte string

        Args:
            source_int (int): Integer to be packed

        Returns:
            bytes: Packed byte string containing integer
        """
        if not isinstance(value, int):
            raise _EX.InvalidDataException(f"Expected integer, got {type(value).__name__}.")

        return pack('>Q', value)

    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a 64-bit integer from a block of bytes

        Args:
            data (bytes): Block of bytes containing an integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        return int(unpack('>Q', data[:8])[0]), data[8:]

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if not isinstance(self.value, int):
            return _EX.InvalidFieldDataException(
                f"Passed value type ({type(self.value)}) is not an integer"
            )

        if self.value > MAX_INT64:
            return _EX.IntegerOverflowException(
                f"Passed value {self.value} is too large for a 64-bit integer"
            )

        return True

class DateTimeField(Integer64Field):
    """
    Certificate field representing a datetime value.
    The value is saved as a 64-bit integer (unix timestamp)
    """
    @staticmethod
    def encode(value: datetime) -> bytes:
        return Integer64Field.encode(int(value.timestamp()))

    @staticmethod
    def decode(data: bytes) -> datetime:
        timestamp, data = Integer64Field.decode(data)

        return datetime.fromtimestamp(
            timestamp
        ), data

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if not isinstance(self.value, datetime):
            return _EX.InvalidFieldDataException(
                f"Passed value type ({type(self.value)}) is not a datetime object"
            )

        return True

class MpIntegerField(StringField):
    """
    Certificate field representing a multiple precision integer,
    an integer too large to fit in 64 bits.
    """
    @staticmethod
    # pylint: disable=arguments-differ
    def encode(value: int) -> bytes:
        """
        Encodes a multiprecision integer (integer larger than 64bit)
        into a packed byte string

        Args:
            value (int): Large integer

        Returns:
            bytes: Packed byte string containing integer
        """
        return StringField.encode(
            long_to_bytes(value)
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a multiprecision integer (integer larger than 64bit)

        Args:
            data (bytes): Block of bytes containing a long (mp) integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        mpint, data = StringField.decode(data)
        return bytes_to_long(mpint), data

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if not isinstance(self.value, int):
            return _EX.InvalidFieldDataException(
                f"Passed value type ({type(self.value)}) is not an integer"
            )

        return True

class StandardListField(CertificateField):
    """
    Certificate field representing a list or tuple of strings
    """
    @staticmethod
    def encode(value: Union[list, tuple]) -> bytes:
        """Encodes a list or tuple to a byte string

        Args:
            source_list (list): list of strings
            null_separator (bool, optional): Insert blank string string between items. Default None

        Returns:
            bytes: Packed byte string containing the source data
        """
        if sum([ not isinstance(item, Union[str, bytes]) for item in value]) > 0:
            raise TypeError("Expected list or tuple containing strings or bytes")

        return StringField.encode(
            b''.join(
                [
                    StringField.encode(x) for x in value
                ]
            )
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[list, bytes]:
        """Decodes a list of strings from a block of bytes

        Args:
            data (bytes): The block of bytes containing a list of strings
        Returns:
            tuple: _description_
        """
        list_bytes, data = StringField.decode(data)

        decoded = []
        while len(list_bytes) > 0:
            elem, list_bytes = StringField.decode(list_bytes)
            decoded.append(elem)

        return decoded, data

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if not isinstance(self.value, Union[list, tuple]):
            return _EX.InvalidFieldDataException(
                f"Passed value type ({type(self.value)}) is not a list/tuple"
            )

        return True

class SeparatedListField(CertificateField):
    """
    Certificate field representing a list or integer in python,
    separated in byte-form by null-bytes.
    """

    @staticmethod
    def encode(value: Union[list, tuple]) -> bytes:
        """
        Encodes a list or tuple to a byte string separated by a null byte

        Args:
            source_list (list): list of strings

        Returns:
            bytes: Packed byte string containing the source data
        """
        if sum([ not isinstance(item, Union[str, bytes]) for item in value ]) > 0:
            raise TypeError("Expected list or tuple containing strings or bytes")

        if len(value) < 1:
            return StandardListField.encode(value)

        null_byte = StringField.encode('')

        return StringField.encode(
            null_byte.join(
                StringField.encode(item) for item in value
            ) + null_byte
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[list, bytes]:
        """Decodes a list of strings from a block of bytes

        Args:
            data (bytes): The block of bytes containing a list of strings
        Returns:
            tuple: _description_
        """
        list_bytes, data = StringField.decode(data)

        decoded = []
        while len(list_bytes) > 0:
            elem, list_bytes = StringField.decode(list_bytes)

            if elem != b'':
                decoded.append(elem)

        return decoded, data

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if not isinstance(self.value, Union[list, tuple]):
            return _EX.InvalidFieldDataException(
                f"Passed value type ({type(self.value)}) is not a list/tuple"
            )

        return True

class PubkeyTypeField(StringField):
    """
    Contains the certificate type, which is based on the
    public key type the certificate is created for, e.g.
    'ssh-ed25519-cert-v01@openssh.com' for an ED25519 key
    """
    def __init__(self, value: str):
        super().__init__(
            value=value,
            name='pubkey_type',
        )

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if self.value not in (
            'ssh-rsa-cert-v01@openssh.com',
            'rsa-sha2-256-cert-v01@openssh.com',
            'rsa-sha2-512-cert-v01@openssh.com',
            'ssh-dss-cert-v01@openssh.com',
            'ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ecdsa-sha2-nistp384-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521-cert-v01@openssh.com',
            'ssh-ed25519-cert-v01@openssh.com'
        ):
            return _EX.InvalidDataException(f"Invalid pubkey type: {self.value}")

        return True

class NonceField(StringField):
    """
    Contains the nonce for the certificate, randomly generated
    this protects the integrity of the private key, especially
    for ecdsa.
    """
    def __init__(self, value: str = None):
        super().__init__(
            value=value if value is not None else generate_secure_nonce(),
            name='nonce'
        )

    def validate(self) -> Union[bool, Exception]:
        """
        Validate the field data
        """
        if len(self.value) < 32:
            self.exception = _EX.InsecureNonceException(
                "Nonce must be at least 32 bytes long to be secure"
            )
            return False

        return True

class PublicKeyField(CertificateField):
    """
    Contains the subject (User or Host) public key for whom/which
    the certificate is created.
    """
    def __init__(self, value: PublicKey):
        super().__init__(
            value=value,
            name='public_key'
        )

    def __str__(self) -> str:
        return ' '.join([
            self.__class__.__name__.replace('PubkeyField', ''),
            self.value.get_fingerprint()
        ])

    @staticmethod
    def encode(value: RSAPublicKey) -> bytes:
        """
        Encode the certificate field to a byte string

        Args:
            value (RSAPublicKey): The public key to encode

        Returns:
            bytes: A byte string with the encoded public key
        """

        return StringField.decode(
            value.raw_bytes()
        )[1]

    @staticmethod
    def from_object(public_key: PublicKey):
        """
        Loads the public key from a sshkey_tools.keys.PublicKey
        class or childclass

        Args:
            public_key (PublicKey): The public key for which to
                                    create the certificate

        Raises:
            _EX.InvalidKeyException: Invalid public key

        Returns:
            PublicKeyField: A child class of PublicKeyField specific
                            to the chosen public key
        """
        try:
            return globals()[SUBJECT_PUBKEY_MAP[public_key.__class__]](
                value=public_key
            )
        except KeyError:
            raise _EX.InvalidKeyException(
                "The public key is invalid"
            ) from KeyError

class RSAPubkeyField(PublicKeyField):
    """
    Holds the RSA Public Key for RSA Certificates
    """

    @staticmethod
    def decode(data: bytes) -> Tuple[RSAPublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[RSAPublicKey, bytes]: The PublicKey field and remainder of the data
        """
        e, data = MpIntegerField.decode(data)
        n, data = MpIntegerField.decode(data)

        return RSAPublicKey.from_numbers(
            e=e,
            n=n
        ), data

    def validate(self) -> Union[bool, Exception]:
        """
        Validates that the field data is a valid RSA Public Key
        """
        if not isinstance(self.value, RSAPublicKey):
            return _EX.InvalidFieldDataException(
                "This public key class is not valid for use in a certificate"
            )

        return True

class DSAPubkeyField(PublicKeyField):
    """
    Holds the DSA Public Key for DSA Certificates
    """

    @staticmethod
    def decode(data: bytes) -> Tuple[DSAPublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[RSAPublicKey, bytes]: The PublicKey field and remainder of the data
        """
        p, data = MpIntegerField.decode(data)
        q, data = MpIntegerField.decode(data)
        g, data = MpIntegerField.decode(data)
        y, data = MpIntegerField.decode(data)

        return DSAPublicKey.from_numbers(
            p=p, q=q, g=g, y=y
        ), data

    def validate(self) -> Union[bool, Exception]:
        """
        Validates that the field data is a valid DSA Public Key
        """
        if not isinstance(self.value, DSAPublicKey):
            return _EX.InvalidFieldDataException(
                "This public key class is not valid for use in a certificate"
            )

        return True

class ECDSAPubkeyField(PublicKeyField):
    """
    Holds the ECDSA Public Key for ECDSA Certificates
    """

    @staticmethod
    def decode(data: bytes) -> Tuple[ECDSAPublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[ECPublicKey, bytes]: The PublicKey field and remainder of the data
        """
        curve, data = StringField.decode(data)
        key, data = StringField.decode(data)

        key_type = b'ecdsa-sha2-' + curve

        return ECDSAPublicKey.from_string(
            key_type + b' ' +
            b64encode(
                StringField.encode(key_type) +
                StringField.encode(curve) +
                StringField.encode(key)
            )
        ), data

    def validate(self) -> Union[bool, Exception]:
        """
        Validates that the field data is a valid ECDSA Public Key
        """
        if not isinstance(self.value, ECDSAPublicKey):
            return _EX.InvalidFieldDataException(
                "This public key class is not valid for use in a certificate"
            )

        return True

class ED25519PubkeyField(PublicKeyField):
    """
    Holds the ED25519 Public Key for ED25519 Certificates
    """

    @staticmethod
    def decode(data: bytes) -> Tuple[ED25519PublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[ED25519PublicKey, bytes]: The PublicKey field and remainder of the data
        """
        pubkey, data = StringField.decode(data)

        return ED25519PublicKey.from_raw_bytes(
            pubkey
        ), data

    def validate(self) -> Union[bool, Exception]:
        """
        Validates that the field data is a valid ED25519 Public Key
        """
        if not isinstance(self.value, ED25519PublicKey):
            return _EX.InvalidFieldDataException(
                "This public key class is not valid for use in a certificate"
            )

        return True

class SerialField(Integer64Field):
    """
    Contains the numeric serial number of the certificate,
    maximum is (2**64)-1
    """
    def __init__(self, value: int):
        super().__init__(
            value=value,
            name='serial'
        )

class CertificateTypeField(Integer32Field):
    """
    Contains the certificate type
    User certificate: CERT_TYPE.USER/1
    Host certificate: CERT_TYPE.HOST/2
    """
    def __init__(self, value: Union[CERT_TYPE, int]):
        super().__init__(
            value=value.value if isinstance(value, CERT_TYPE) else value,
            name='type'
        )

    def validate(self) -> Union[bool, Exception]:
        """
        Validates that the field contains a valid type
        """
        if 0 > self.value > 3:
            self.exception = _EX.InvalidDataException(
                "The certificate type is invalid (1: User, 2: Host)"
            )
            return False

        return True

class KeyIDField(StringField):
    """
    Contains the key identifier (subject) of the certificate,
    alphanumeric string
    """
    def __init__(self, value: str):
        super().__init__(
            value=value,
            name='key_id'
        )

    def validate(self) -> Union[bool, Exception]:
        """
        Validates that the field is set and not empty
        """
        if self.value in [None, False, '', ' ']:
            return _EX.InvalidDataException(
                "You need to provide a Key ID"
            )

        return True

class PrincipalsField(StandardListField):
    """
    Contains a list of principals for the certificate,
    e.g. SERVERHOSTNAME01 or all-web-servers
    """
    def __init__(self, value: Union[list, tuple]):
        super().__init__(
            value=list(value),
            name='principals'
        )

class ValidityStartField(DateTimeField):
    """
    Contains the start of the validity period for the certificate,
    represented by a datetime object
    """
    def __init__(self, value: datetime):
        super().__init__(
            value=value,
            name='valid_after'
        )

class ValidityEndField(DateTimeField):
    """
    Contains the end of the validity period for the certificate,
    represented by a datetime object
    """
    def __init__(self, value: datetime):
        super().__init__(
            value=value,
            name='valid_before'
        )

class CriticalOptionsField(SeparatedListField):
    """
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

    """
    def __init__(self, value: Union[list, tuple]):
        super().__init__(
            value=value,
            name='critical_options'
        )

    def validate(self) -> Union[bool, Exception]:
        """
        Validate that the field contains a valid list of options
        """
        valid_opts = (
            'force-command',
            'source-address',
            'verify-required'
        )

        for item in self.value:
            split = item.split('=')
            if split[0] not in valid_opts:
                return _EX.InvalidFieldDataException(
                    f"The option {item} is invalid"
                )

        return True

class ExtensionsField(SeparatedListField):
    """
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

    """
    def __init__(self, value: Union[list, tuple]):
        super().__init__(
            value=value,
            name='extensions'
        )

    def validate(self) -> Union[bool, Exception]:
        """
        Validates that the options provided are valid
        """
        valid_opts = (
            'no-touch-required',
            'permit-X11-forwarding',
            'permit-agent-forwarding',
            'permit-port-forwarding',
            'permit-pty',
            'permit-user-rc'
        )

        for item in self.value:
            if item not in valid_opts:
                self.exception = _EX.InvalidDataException(
                    f"The extension '{item}' is invalid"
                )
                return False

        return True

class ReservedField(StringField):
    """
    This field is reserved for future use, and
    doesn't contain any actual data, just an empty string.
    """
    def __init__(self, value: str = ''):
        super().__init__(
            value=value,
            name='reserved'
        )

    def validate(self) -> Union[bool, Exception]:
        """
        Validate that the field only contains an empty string
        """
        if self.value == '':
            return True

        return _EX.InvalidDataException(
            "The reserved field needs to be an empty string"
        )

class CAPublicKeyField(StringField):
    """
    Contains the public key of the certificate authority
    that is used to sign the certificate.
    """
    def __init__(self, value: PublicKey):
        super().__init__(
            value=value,
            name='ca_public_key'
        )

    def __str__(self) -> str:
        return ' '.join([
            (
                self.
                value.
                __class__.
                __name__.replace('PublicKey', '').
                replace('EllipticCurve', 'ECDSA')
            ),
            self.value.get_fingerprint()
        ])

    def validate(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if self.value in [None, False, '', ' ']:
            return _EX.InvalidFieldDataException(
                "You need to provide a CA public key"
            )

        if not isinstance(self.value, PublicKey):
            return _EX.InvalidFieldDataException(
                "The CA public key needs to be a sshkey_tools.keys.PublicKey object"
            )

        return True

    @staticmethod
    def decode(data) -> Tuple[PublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[PublicKey, bytes]: The PublicKey field and remainder of the data
        """
        pubkey, data = StringField.decode(data)
        pubkey_type = StringField.decode(pubkey)[0]

        return PublicKey.from_string(
            f"{pubkey_type.decode('utf-8')} {b64encode(pubkey).decode('utf-8')}"
        ), data

    def __bytes__(self) -> bytes:
        return self.encode(
            self.value.raw_bytes()
        )

    @classmethod
    def from_object(cls, public_key: PublicKey) -> 'CAPublicKeyField':
        """
        Creates a new CAPublicKeyField from a PublicKey object
        """
        return cls(
            value=public_key
        )


class SignatureField(CertificateField):
    """
    Creates and contains the signature of the certificate
    """
    # pylint: disable=super-init-not-called
    def __init__(
        self,
        private_key: PrivateKey = None,
        signature: bytes = None
    ):
        self.name = 'signature'
        self.private_key = private_key
        self.is_signed = False
        self.value = signature

    @staticmethod
    def from_object(private_key: PrivateKey):
        """
        Load a private key from a PrivateKey object


        Args:
            private_key (PrivateKey): Private key to use for signing

        Raises:
            _EX.InvalidKeyException: Invalid private key

        Returns:
            SignatureField: SignatureField child class
        """
        try:
            return globals()[CA_SIGNATURE_MAP[private_key.__class__]](
                private_key=private_key
            )
        except KeyError:
            raise _EX.InvalidKeyException(
                'The private key provided is invalid or not supported'
            ) from KeyError

    @staticmethod
    def from_decode(data: bytes) -> Tuple['SignatureField', bytes]:
        """
        Generates a SignatureField child class from the encoded signature

        Args:
            data (bytes): The bytestring containing the encoded signature

        Raises:
            _EX.InvalidDataException: Invalid data

        Returns:
            SignatureField: child of SignatureField
        """
        signature, _ = StringField.decode(data)
        signature_type = StringField.decode(signature)[0]

        for key, value in SIGNATURE_TYPE_MAP.items():
            if key in signature_type:
                return globals()[value].from_decode(
                    data
                )

        raise _EX.InvalidDataException(
            "No matching signature type found"
        )

    def can_sign(self):
        """
        Determines if a signature can be generated from
        this private key
        """
        return self.private_key is not None

    def sign(self, data: bytes) -> None:
        """
        Placeholder signing function
        """

    def __bytes__(self) -> None:
        return self.encode(
            self.value
        )

class RSASignatureField(SignatureField):
    """
    Creates and contains the RSA signature from an RSA Private Key
    """
    def __init__(
        self,
        private_key: RSAPrivateKey = None,
        hash_alg: RsaAlgs = RsaAlgs.SHA512,
        signature: bytes = None
    ):
        super().__init__(private_key, signature)
        self.hash_alg = hash_alg

    @staticmethod
    #pylint: disable=arguments-renamed
    def encode(signature: bytes, hash_alg: RsaAlgs = RsaAlgs.SHA256) -> bytes:
        """
        Encodes the signature to a byte string

        Args:
            signature (bytes): The signature bytes to encode
            hash_alg (RsaAlgs, optional):  The hash algorithm used for the signature.
                                            Defaults to RsaAlgs.SHA256.

        Returns:
            bytes: The encoded byte string
        """
        return StringField.encode(
            StringField.encode(hash_alg.value[0]) +
            StringField.encode(signature)
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[
        Tuple[
            bytes,
            bytes
        ],
        bytes
    ]:
        """
        Decodes a bytestring containing a signature

        Args:
            data (bytes): The bytestring starting with the RSA Signature

        Returns:
            Tuple[ Tuple[ bytes, bytes ], bytes ]: (signature_type, signature), remainder of data
        """
        signature, data = StringField.decode(data)

        sig_type, signature = StringField.decode(signature)
        signature, _ = StringField.decode(signature)

        return (sig_type, signature), data

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['RSASignatureField', bytes]:
        """
        Generates an RSASignatureField class from the encoded signature

        Args:
            data (bytes): The bytestring containing the encoded signature

        Raises:
            _EX.InvalidDataException: Invalid data

        Returns:
            Tuple[RSASignatureField, bytes]: RSA Signature field and remainder of data
        """
        signature, data = cls.decode(data)

        return cls(
            private_key=None,
            hash_alg=[alg for alg in RsaAlgs if alg.value[0] == signature[0].decode('utf-8')][0],
            signature=signature[1]
        ), data

    def sign(
        self,
        data: bytes,
        hash_alg: RsaAlgs = RsaAlgs.SHA256
    ) -> None:
        """
        Signs the provided data with the provided private key

        Args:
            data (bytes): The data to be signed
            hash_alg (RsaAlgs, optional): The RSA algorithm to use for hashing.
                                           Defaults to RsaAlgs.SHA256.
        """
        self.value = self.private_key.sign(
            data,
            hash_alg
        )

        self.hash_alg = hash_alg
        self.is_signed = True

    def __bytes__(self):
        return self.encode(
            self.value,
            self.hash_alg
        )


class DSASignatureField(SignatureField):
    """
    Creates and contains the DSA signature from an DSA Private Key
    """
    def __init__(
        self,
        private_key: DSAPrivateKey = None,
        signature: bytes = None
    ) -> None:
        super().__init__(private_key, signature)

    @staticmethod
    # pylint: disable=arguments-renamed
    def encode(signature: bytes):
        """
        Encodes the signature to a byte string

        Args:
            signature (bytes): The signature bytes to encode

        Returns:
            bytes: The encoded byte string
        """
        r, s = decode_dss_signature(signature)

        return StringField.encode(
            StringField.encode('ssh-dss') +
            StringField.encode(
                long_to_bytes(r, 20) +
                long_to_bytes(s, 20)
            )
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[bytes, bytes]:
        """
        Decodes a bytestring containing a signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ bytes, bytes ]: signature, remainder of the data
        """
        signature, data = StringField.decode(data)

        signature = StringField.decode(
            StringField.decode(signature)[1]
        )[0]
        r = bytes_to_long(signature[:20])
        s = bytes_to_long(signature[20:])

        signature = encode_dss_signature(r, s)

        return signature, data

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['DSASignatureField', bytes]:
        """
        Creates a signature field class from the encoded signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ DSASignatureField, bytes ]: signature, remainder of the data
        """
        signature, data = cls.decode(data)

        return cls(
            private_key=None,
            signature=signature
        ), data

    def sign(self, data: bytes) -> None:
        """
        Signs the provided data with the provided private key

        Args:
            data (bytes): The data to be signed
        """
        self.value = self.private_key.sign(
            data
        )
        self.is_signed = True

class ECDSASignatureField(SignatureField):
    """
    Creates and contains the ECDSA signature from an ECDSA Private Key
    """
    def __init__(
        self,
        private_key: ECDSAPrivateKey = None,
        signature: bytes = None,
        curve_name: str = None
    ) -> None:
        super().__init__(private_key, signature)

        if curve_name is None:
            curve_size = self.private_key.public_key.key.curve.key_size
            curve_name = f'ecdsa-sha2-nistp{curve_size}'

        self.curve = curve_name

    @staticmethod
    #pylint: disable=arguments-renamed
    def encode(signature: bytes, curve_name: str = None) -> bytes:
        """
        Encodes the signature to a byte string

        Args:
            signature (bytes): The signature bytes to encode
            curve_name (str): The name of the curve used for the signature
                              private key

        Returns:
            bytes: The encoded byte string
        """
        r, s = decode_dss_signature(signature)

        return StringField.encode(
            StringField.encode(
                curve_name
            ) +
            StringField.encode(
                MpIntegerField.encode(r) +
                MpIntegerField.encode(s)
            )
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[ Tuple[ bytes, bytes ], bytes]:
        """
        Decodes a bytestring containing a signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ Tuple[ bytes, bytes ], bytes]: (curve, signature), remainder of the data
        """
        signature, data = StringField.decode(data)

        curve, signature = StringField.decode(signature)
        signature, _ = StringField.decode(signature)

        r, signature = MpIntegerField.decode(signature)
        s, _ = MpIntegerField.decode(signature)

        signature = encode_dss_signature(r, s)

        return (curve, signature), data

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['ECDSASignatureField', bytes]:
        """
        Creates a signature field class from the encoded signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ ECDSASignatureField , bytes ]: signature, remainder of the data
        """
        signature, data = cls.decode(data)

        return cls(
            private_key=None,
            signature = signature[1],
            curve_name = signature[0]
        ), data

    def sign(self, data: bytes) -> None:
        """
        Signs the provided data with the provided private key

        Args:
            data (bytes): The data to be signed
        """
        self.value = self.private_key.sign(
            data
        )
        self.is_signed = True

    def __bytes__(self):
        return self.encode(
            self.value,
            self.curve
        )

class ED25519SignatureField(SignatureField):
    """
    Creates and contains the ED25519 signature from an ED25519 Private Key
    """
    def __init__(
        self,
        private_key: ED25519PrivateKey = None,
        signature: bytes = None
    ) -> None:
        super().__init__(private_key, signature)

    @staticmethod
    # pylint: disable=arguments-renamed
    def encode(signature: bytes) -> None:
        """
        Encodes the signature to a byte string

        Args:
            signature (bytes): The signature bytes to encode

        Returns:
            bytes: The encoded byte string
        """
        return StringField.encode(
            StringField.encode('ssh-ed25519') +
            StringField.encode(signature)
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[bytes, bytes]:
        """
        Decodes a bytestring containing a signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ bytes, bytes ]: signature, remainder of the data
        """
        signature, data = StringField.decode(data)

        signature = StringField.decode(
            StringField.decode(signature)[1]
        )[0]

        return signature, data

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['ED25519SignatureField', bytes]:
        """
        Creates a signature field class from the encoded signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ ED25519SignatureField , bytes ]: signature, remainder of the data
        """
        signature, data = cls.decode(data)

        return cls(
            private_key=None,
            signature=signature
        ), data

    def sign(self, data: bytes) -> None:
        """
        Signs the provided data with the provided private key

        Args:
            data (bytes): The data to be signed
            hash_alg (RsaAlgs, optional): The RSA algorithm to use for hashing.
                                           Defaults to RsaAlgs.SHA256.
        """
        self.value = self.private_key.sign(
            data
        )
        self.is_signed = True
