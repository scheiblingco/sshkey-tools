"""
Field types for SSH Certificates
"""
# pylint: disable=invalid-name,too-many-lines,arguments-differ
import re
from base64 import b64encode
from datetime import datetime, timedelta
from enum import Enum
from struct import pack, unpack
from typing import Tuple, Union

from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from . import exceptions as _EX
from .keys import (
    DsaPrivateKey,
    DsaPublicKey,
    EcdsaPrivateKey,
    EcdsaPublicKey,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    PrivateKey,
    PublicKey,
    RsaAlgs,
    RsaPrivateKey,
    RsaPublicKey,
)
from .utils import (
    bytes_to_long,
    concat_to_string,
    ensure_bytestring,
    ensure_string,
    generate_secure_nonce,
    long_to_bytes,
    random_keyid,
    random_serial,
)

NoneType = type(None)
MAX_INT32 = 2**32
MAX_INT64 = 2**64
NEWLINE = "\n"

ECDSA_CURVE_MAP = {
    "secp256r1": "nistp256",
    "secp384r1": "nistp384",
    "secp521r1": "nistp521",
}

SUBJECT_PUBKEY_MAP = {
    RsaPublicKey: "RsaPubkeyField",
    DsaPublicKey: "DsaPubkeyField",
    EcdsaPublicKey: "EcdsaPubkeyField",
    Ed25519PublicKey: "Ed25519PubkeyField",
}

CA_SIGNATURE_MAP = {
    RsaPrivateKey: "RsaSignatureField",
    DsaPrivateKey: "DsaSignatureField",
    EcdsaPrivateKey: "EcdsaSignatureField",
    Ed25519PrivateKey: "Ed25519SignatureField",
}

SIGNATURE_TYPE_MAP = {
    b"rsa": "RsaSignatureField",
    b"dss": "DsaSignatureField",
    b"ecdsa": "EcdsaSignatureField",
    b"ed25519": "Ed25519SignatureField",
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

    IS_SET = None
    DEFAULT = None
    REQUIRED = False
    DATA_TYPE = NoneType

    def __init__(self, value=None):
        self.value = value
        self.exception = None
        self.IS_SET = True
        self.name = self.get_name()

    def __table__(self):
        return (str(self.name), str(self.value))

    def __str__(self):
        return f"{self.name}: {self.value}"

    def __bytes__(self) -> bytes:
        return self.encode(self.value)

    @classmethod
    def get_name(cls) -> str:
        """
        Fetch the name of the field (identifier format)

        Returns:
            str: The name/id of the field
        """
        return "_".join(re.findall("[A-Z][^A-Z]*", cls.__name__)[:-1]).lower()

    @classmethod
    def __validate_type__(cls, value, do_raise: bool = False) -> Union[bool, Exception]:
        """
        Validate the data type of the value against the class data type
        """
        if not isinstance(value, cls.DATA_TYPE):
            ex = _EX.InvalidDataException(
                f"Invalid data type for {cls.get_name()}"
                + f"(expected {cls.DATA_TYPE}, got {type(value)})"
            )

            if do_raise:
                raise ex

            return ex

        return True

    def __validate_required__(self) -> Union[bool, Exception]:
        """
        Validates if the field is set when required
        """
        if self.DEFAULT == self.value is None:
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} is a required field"
            )
        return True

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        Meant to be overridden by child classes
        """
        return True

    # pylint: disable=not-callable
    def validate(self) -> bool:
        """
        Validates all field contents and types
        """
        if isinstance(self.value, NoneType) and self.DEFAULT is not None:
            self.value = self.DEFAULT() if callable(self.DEFAULT) else self.DEFAULT

        self.exception = (
            self.__validate_type__(self.value),
            self.__validate_required__(),
            self.__validate_value__(),
        )

        return self.exception == (True, True, True)

    @staticmethod
    def decode(data: bytes) -> tuple:
        """
        Returns the decoded value of the field
        """

    @classmethod
    def encode(cls, value) -> bytes:
        """
        Returns the encoded value of the field
        """

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple["CertificateField", bytes]:
        """
        Creates a field class based on encoded bytes

        Returns:
            tuple: CertificateField, remaining bytes
        """
        value, data = cls.decode(data)
        return cls(value), data

    @classmethod
    # pylint: disable=not-callable
    def factory(cls, blank: bool = False) -> "CertificateField":
        """
        Factory to create field with default value if set, otherwise empty

        Args:
            blank (bool): Return a blank class (for decoding)

        Returns:
            CertificateField: A new CertificateField subclass instance
        """
        if cls.DEFAULT is None or blank:
            return cls

        if callable(cls.DEFAULT):
            return cls(cls.DEFAULT())

        return cls(cls.DEFAULT)


class BooleanField(CertificateField):
    """
    Field representing a boolean value (True/False) or (1/0)
    """

    DATA_TYPE = (bool, int)

    @classmethod
    def encode(cls, value: Union[int, bool]) -> bytes:
        """
        Encodes a boolean value to a byte string

        Args:
            value (bool): Boolean to encode

        Returns:
            bytes: Packed byte representing the boolean
        """
        cls.__validate_type__(value, True)
        return pack("B", 1 if value else 0)

    @staticmethod
    def decode(data: bytes) -> Tuple[bool, bytes]:
        """
        Decodes a boolean from a bytestring

        Args:
            data (bytes): The byte string starting with an encoded boolean
        """
        return bool(unpack("B", data[:1])[0]), data[1:]

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        return (
            True
            if self.value in (True, False, 1, 0)
            else _EX.InvalidFieldDataException(
                f"{self.get_name()} must be a boolean (True/1 or False/0)"
            )
        )


class BytestringField(CertificateField):
    """
    Field representing a bytestring value
    """

    DATA_TYPE = (bytes, str)
    DEFAULT = b""

    @classmethod
    def encode(cls, value: bytes) -> bytes:
        """
        Encodes a string or bytestring into a packed byte string

        Args:
            value (Union[str, bytes]): The string/bytestring to encode
            encoding (str): The encoding to user for the string

        Returns:
            bytes: Packed byte string containing the source data
        """
        cls.__validate_type__(value, True)
        return pack(">I", len(value)) + ensure_bytestring(value)

    @staticmethod
    def decode(data: bytes) -> Tuple[bytes, bytes]:
        """
        Unpacks the next string from a packed byte string

        Args:
            data (bytes): The packed byte string to unpack

        Returns:
            tuple(bytes, bytes):  The next block of bytes from the packed byte
                                  string and remainder of the data
        """
        length = unpack(">I", data[:4])[0] + 4
        return ensure_bytestring(data[4:length]), data[length:]


class StringField(BytestringField):
    """
    Field representing a string value
    """

    DATA_TYPE = (str, bytes)
    DEFAULT = ""

    @classmethod
    def encode(cls, value: str, encoding: str = "utf-8"):
        """
        Encodes a string or bytestring into a packed byte string

        Args:
            value (Union[str, bytes]): The string/bytestring to encode
            encoding (str): The encoding to user for the string

        Returns:
            bytes: Packed byte string containing the source data
        """
        cls.__validate_type__(value, True)
        return BytestringField.encode(ensure_bytestring(value, encoding))

    @staticmethod
    def decode(data: bytes, encoding: str = "utf-8") -> Tuple[str, bytes]:
        """
        Unpacks the next string from a packed byte string

        Args:
            data (bytes): The packed byte string to unpack

        Returns:
            tuple(bytes, bytes):  The next block of bytes from the packed byte
                                  string and remainder of the data
        """
        value, data = BytestringField.decode(data)

        return value.decode(encoding), data


class Integer32Field(CertificateField):
    """
    Certificate field representing a 32-bit integer
    """

    DATA_TYPE = int
    DEFAULT = 0

    @classmethod
    def encode(cls, value: int) -> bytes:
        """Encodes a 32-bit integer value to a packed byte string

        Args:
            source_int (int): Integer to be packed

        Returns:
            bytes: Packed byte string containing integer
        """
        cls.__validate_type__(value, True)
        return pack(">I", value)

    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a 32-bit integer from a block of bytes

        Args:
            data (bytes): Block of bytes containing an integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        return int(unpack(">I", data[:4])[0]), data[4:]

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        if self.value < MAX_INT32:
            return True

        return _EX.InvalidFieldDataException(
            f"{self.get_name()} must be a 32-bit integer"
        )


class Integer64Field(CertificateField):
    """
    Certificate field representing a 64-bit integer
    """

    DATA_TYPE = int
    DEFAULT = 0

    @classmethod
    def encode(cls, value: int) -> bytes:
        """Encodes a 64-bit integer value to a packed byte string

        Args:
            source_int (int): Integer to be packed

        Returns:
            bytes: Packed byte string containing integer
        """
        cls.__validate_type__(value, True)
        return pack(">Q", value)

    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a 64-bit integer from a block of bytes

        Args:
            data (bytes): Block of bytes containing an integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        return int(unpack(">Q", data[:8])[0]), data[8:]

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        if self.value < MAX_INT64:
            return True

        return _EX.InvalidFieldDataException(
            f"{self.get_name()} must be a 64-bit integer"
        )


class DateTimeField(Integer64Field):
    """
    Certificate field representing a datetime value.
    The value is saved as a 64-bit integer (unix timestamp)
    """

    DATA_TYPE = (datetime, int)
    DEFAULT = datetime.now

    @classmethod
    def encode(cls, value: Union[datetime, int]) -> bytes:
        """Encodes a datetime object to a byte string

        Args:
            value (datetime): Datetime object

        Returns:
            bytes: Packed byte string containing datetime timestamp
        """
        cls.__validate_type__(value, True)

        if isinstance(value, datetime):
            value = int(value.timestamp())

        return Integer64Field.encode(value)

    @staticmethod
    def decode(data: bytes) -> datetime:
        """Decodes a datetime object from a block of bytes

        Args:
            data (bytes): Block of bytes containing a datetime object

        Returns:
            tuple: Tuple with datetime and remainder of data
        """
        timestamp, data = Integer64Field.decode(data)
        return datetime.fromtimestamp(timestamp), data

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        check = self.value if isinstance(self.value, int) else self.value.timestamp()

        if check < MAX_INT64:
            return True

        return _EX.InvalidFieldDataException(
            f"{self.get_name()} must be a 64-bit integer or datetime object"
        )


class MpIntegerField(BytestringField):
    """
    Certificate field representing a multiple precision integer,
    an integer too large to fit in 64 bits.
    """

    DATA_TYPE = int
    DEFAULT = 0

    @classmethod
    def encode(cls, value: int) -> bytes:
        """
        Encodes a multiprecision integer (integer larger than 64bit)
        into a packed byte string

        Args:
            value (int): Large integer

        Returns:
            bytes: Packed byte string containing integer
        """
        cls.__validate_type__(value, True)
        return BytestringField.encode(long_to_bytes(value))

    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a multiprecision integer (integer larger than 64bit)

        Args:
            data (bytes): Block of bytes containing a long (mp) integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        mpint, data = BytestringField.decode(data)
        return bytes_to_long(mpint), data


class ListField(CertificateField):
    """
    Certificate field representing a list or tuple of strings
    """

    DATA_TYPE = (list, set, tuple)
    DEFAULT = []

    @classmethod
    def encode(cls, value: Union[list, tuple, set]) -> bytes:
        """Encodes a list or tuple to a byte string

        Args:
            source_list (list): list of strings
            null_separator (bool, optional): Insert blank string string between items. Default None

        Returns:
            bytes: Packed byte string containing the source data
        """
        cls.__validate_type__(value, True)

        try:
            if sum(not isinstance(item, (str, bytes)) for item in value) > 0:
                raise TypeError
        except TypeError:
            raise _EX.InvalidFieldDataException(
                "Expected list or tuple containing strings or bytes"
            ) from TypeError

        return BytestringField.encode(b"".join([StringField.encode(x) for x in value]))

    @staticmethod
    def decode(data: bytes) -> Tuple[list, bytes]:
        """Decodes a list of strings from a block of bytes

        Args:
            data (bytes): The block of bytes containing a list of strings
        Returns:
            tuple: _description_
        """
        list_bytes, data = BytestringField.decode(data)

        decoded = []
        while len(list_bytes) > 0:
            elem, list_bytes = StringField.decode(list_bytes)
            decoded.append(elem)

        return ensure_string(decoded), data

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        if hasattr(self.value, "__iter__") and not all(
            (isinstance(val, (str, bytes)) for val in self.value)
        ):
            return _EX.InvalidFieldDataException(
                "Expected list or tuple containing strings or bytes"
            )
        return True


class KeyValueField(CertificateField):
    """
    Certificate field representing a list or integer in python,
    separated in byte-form by null-bytes.
    """

    DATA_TYPE = (list, tuple, set, dict)
    DEFAULT = {}

    @classmethod
    def encode(cls, value: Union[list, tuple, dict, set]) -> bytes:
        """
        Encodes a dict, set, list or tuple into a key-value byte string.
        If a set, list or tuple is provided, the items are considered keys
        and added with empty values.

        Args:
            source_list (dict, set, list, tuple): list of strings

        Returns:
            bytes: Packed byte string containing the source data
        """
        cls.__validate_type__(value, True)

        if not isinstance(value, dict):
            value = {item: "" for item in value}

        list_data = b""

        for key, item in value.items():
            list_data += StringField.encode(key)

            item = (
                StringField.encode("")
                if item in ["", b""]
                else ListField.encode(
                    [item] if isinstance(item, (str, bytes)) else item
                )
            )

            list_data += item

        return BytestringField.encode(list_data)

    @staticmethod
    def decode(data: bytes) -> Tuple[dict, bytes]:
        """Decodes a list of strings from a block of bytes

        Args:
            data (bytes): The block of bytes containing a list of strings
        Returns:
            tuple: _description_
        """
        list_bytes, data = BytestringField.decode(data)

        decoded = {}
        while len(list_bytes) > 0:
            key, list_bytes = StringField.decode(list_bytes)
            value, list_bytes = BytestringField.decode(list_bytes)

            if value != b"":
                value = StringField.decode(value)[0]

            decoded[key] = value

        decoded = ensure_string(decoded)

        if "".join(decoded.values()) == "":
            return list(decoded.keys()), data

        return decoded, data

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        testvals = (
            self.value
            if not isinstance(self.value, dict)
            else list(self.value.keys()) + list(self.value.values())
        )

        if hasattr(self.value, "__iter__") and not all(
            (isinstance(val, (str, bytes)) for val in testvals)
        ):
            return _EX.InvalidFieldDataException(
                "Expected dict, list, tuple, set with string or byte keys and values"
            )

        return True


class PubkeyTypeField(StringField):
    """
    Contains the certificate type, which is based on the
    public key type the certificate is created for, e.g.
    'ssh-ed25519-cert-v01@openssh.com' for an ED25519 key
    """

    DEFAULT = None
    DATA_TYPE = (str, bytes)
    ALLOWED_VALUES = (
        "ssh-rsa-cert-v01@openssh.com",
        "rsa-sha2-256-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com",
        "ssh-dss-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
    )

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        if ensure_string(self.value) not in self.ALLOWED_VALUES:
            return _EX.InvalidFieldDataException(
                "Expected one of the following values: " +
                NEWLINE.join(self.ALLOWED_VALUES)
            )

        return True


class NonceField(StringField):
    """
    Contains the nonce for the certificate, randomly generated
    this protects the integrity of the private key, especially
    for ecdsa.
    """

    DEFAULT = generate_secure_nonce
    DATA_TYPE = (str, bytes)

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        if hasattr(self.value, "__count__") and len(self.value) < 32:
            return _EX.InvalidFieldDataException(
                "Expected a nonce of at least 32 bytes"
            )

        return True


class PublicKeyField(CertificateField):
    """
    Contains the subject (User or Host) public key for whom/which
    the certificate is created.
    """

    DEFAULT = None
    DATA_TYPE = PublicKey

    def __table__(self) -> tuple:
        return [str(self.name), str(self.value.get_fingerprint())]

    def __str__(self) -> str:
        return " ".join(
            [
                self.__class__.__name__.replace("PubkeyField", ""),
                self.value.get_fingerprint(),
            ]
        )

    @classmethod
    def encode(cls, value: PublicKey) -> bytes:
        """
        Encode the certificate field to a byte string

        Args:
            value (RsaPublicKey): The public key to encode

        Returns:
            bytes: A byte string with the encoded public key
        """
        cls.__validate_type__(value, True)
        return BytestringField.decode(value.raw_bytes())[1]

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
            return globals()[SUBJECT_PUBKEY_MAP[public_key.__class__]](value=public_key)
        except KeyError:
            raise _EX.InvalidKeyException("The public key is invalid") from KeyError


class RsaPubkeyField(PublicKeyField):
    """
    Holds the RSA Public Key for RSA Certificates
    """

    DEFAULT = None
    DATA_TYPE = RsaPublicKey

    @staticmethod
    def decode(data: bytes) -> Tuple[RsaPublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[RsaPublicKey, bytes]: The PublicKey field and remainder of the data
        """
        e, data = MpIntegerField.decode(data)
        n, data = MpIntegerField.decode(data)

        return RsaPublicKey.from_numbers(e=e, n=n), data


class DsaPubkeyField(PublicKeyField):
    """
    Holds the DSA Public Key for DSA Certificates
    """

    DEFAULT = None
    DATA_TYPE = DsaPublicKey

    @staticmethod
    def decode(data: bytes) -> Tuple[DsaPublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[RsaPublicKey, bytes]: The PublicKey field and remainder of the data
        """
        p, data = MpIntegerField.decode(data)
        q, data = MpIntegerField.decode(data)
        g, data = MpIntegerField.decode(data)
        y, data = MpIntegerField.decode(data)

        return DsaPublicKey.from_numbers(p=p, q=q, g=g, y=y), data


class EcdsaPubkeyField(PublicKeyField):
    """
    Holds the ECDSA Public Key for ECDSA Certificates
    """

    DEFAULT = None
    DATA_TYPE = EcdsaPublicKey

    @staticmethod
    def decode(data: bytes) -> Tuple[EcdsaPublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[ECPublicKey, bytes]: The PublicKey field and remainder of the data
        """
        curve, data = StringField.decode(data)
        key, data = BytestringField.decode(data)

        key_type = "ecdsa-sha2-" + curve

        return (
            EcdsaPublicKey.from_string(
                key_type
                + " "
                + b64encode(
                    StringField.encode(key_type)
                    + StringField.encode(curve)
                    + BytestringField.encode(key)
                ).decode("utf-8")
            ),
            data,
        )


class Ed25519PubkeyField(PublicKeyField):
    """
    Holds the ED25519 Public Key for ED25519 Certificates
    """

    DEFAULT = None
    DATA_TYPE = Ed25519PublicKey

    @staticmethod
    def decode(data: bytes) -> Tuple[Ed25519PublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[Ed25519PublicKey, bytes]: The PublicKey field and remainder of the data
        """
        pubkey, data = BytestringField.decode(data)

        return Ed25519PublicKey.from_raw_bytes(pubkey), data


class SerialField(Integer64Field):
    """
    Contains the numeric serial number of the certificate,
    maximum is (2**64)-1
    """

    DEFAULT = random_serial
    DATA_TYPE = int


class CertificateTypeField(Integer32Field):
    """
    Contains the certificate type
    User certificate: CERT_TYPE.USER/1
    Host certificate: CERT_TYPE.HOST/2
    """

    DEFAULT = CERT_TYPE.USER
    DATA_TYPE = (CERT_TYPE, int)
    ALLOWED_VALUES = (CERT_TYPE.USER, CERT_TYPE.HOST, 1, 2)

    @classmethod
    def encode(cls, value: Union[CERT_TYPE, int]) -> bytes:
        """
        Encode the certificate type field to a byte string

        Args:
            value (Union[CERT_TYPE, int]): The type of the certificate

        Returns:
            bytes: A byte string with the encoded public key
        """
        cls.__validate_type__(value, True)

        if isinstance(value, CERT_TYPE):
            value = value.value

        return Integer32Field.encode(value)

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        if self.value not in self.ALLOWED_VALUES:
            return _EX.InvalidCertificateFieldException(
                "The certificate type is invalid (expected int(1,2) or CERT_TYPE.X)"
            )

        return True


class KeyIdField(StringField):
    """
    Contains the key identifier (subject) of the certificate,
    alphanumeric string
    """

    DEFAULT = random_keyid
    DATA_TYPE = (str, bytes)


class PrincipalsField(ListField):
    """
    Contains a list of principals for the certificate,
    e.g. SERVERHOSTNAME01 or all-web-servers.
    If no principals are added, the certificate is valid
    only for servers that have no allowed principals specified
    """

    DEFAFULT = []
    DATA_TYPE = (list, set, tuple)


class ValidAfterField(DateTimeField):
    """
    Contains the start of the validity period for the certificate,
    represented by a datetime object
    """

    DEFAULT = datetime.now()
    DATA_TYPE = (datetime, int)


class ValidBeforeField(DateTimeField):
    """
    Contains the end of the validity period for the certificate,
    represented by a datetime object
    """

    DEFAULT = datetime.now() + timedelta(minutes=10)
    DATA_TYPE = (datetime, int)

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        Additional checks over standard datetime field are
        done to ensure no already expired certificates are
        created
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        super().__validate_value__()
        check = (
            self.value
            if isinstance(self.value, datetime)
            else datetime.fromtimestamp(self.value)
        )

        if check < datetime.now():
            return _EX.InvalidCertificateFieldException(
                "The certificate validity period is invalid"
                + " (expected a future datetime object or timestamp)"
            )

        return True


class CriticalOptionsField(KeyValueField):
    """
    Contains the critical options part of the certificate (optional).
    This should be a list of strings with one of the following

    options:
        force-command=<command>
            Limits the connecting user to a specific command,
            e.g. sftp-internal
        source-address=<ip_address>
            Limits the user to connect only from a certain
            ip, subnet or host
        verify-required=<true|false>
            If set to true, the user must verify their identity
            if using a hardware token
    """

    DEFAULT = []
    DATA_TYPE = (list, set, tuple, dict)
    ALLOWED_VALUES = ("force-command", "source-address", "verify-required")

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        for elem in (
            self.value if not isinstance(self.value, dict) else list(self.value.keys())
        ):
            if elem not in self.ALLOWED_VALUES:
                return _EX.InvalidCertificateFieldException(
                    f"Critical option not recognized ({elem}){NEWLINE}"
                    + f"Valid options are {', '.join(self.ALLOWED_VALUES)}"
                )

        return True


class ExtensionsField(KeyValueField):
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

    DEFAULT = []
    DATA_TYPE = (list, set, tuple, dict)
    ALLOWED_VALUES = (
        "no-touch-required",
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    )

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        for item in self.value:
            if item not in self.ALLOWED_VALUES:
                return _EX.InvalidDataException(
                    f"Invalid extension '{item}'{NEWLINE}"
                    + f"Allowed values are: {NEWLINE.join(self.ALLOWED_VALUES)}"
                )

        return True


class ReservedField(StringField):
    """
    This field is reserved for future use, and
    doesn't contain any actual data, just an empty string.
    """

    DEFAULT = ""
    DATA_TYPE = str

    def __validate_value__(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if isinstance(self.__validate_type__(self.value), Exception):
            return _EX.InvalidFieldDataException(
                f"{self.get_name()} Could not validate value, invalid type"
            )

        return (
            True
            if self.value == ""
            else _EX.InvalidDataException("The reserved field is not empty")
        )


class CAPublicKeyField(BytestringField):
    """
    Contains the public key of the certificate authority
    that is used to sign the certificate.
    """

    DEFAULT = None
    DATA_TYPE = (str, bytes)

    def __str__(self) -> str:
        return " ".join(
            [
                (
                    self.value.__class__.__name__.replace("PublicKey", "").replace(
                        "EllipticCurve", "ECDSA"
                    )
                ),
                self.value.get_fingerprint(),
            ]
        )

    def __bytes__(self) -> bytes:
        return self.encode(self.value.raw_bytes())

    def __table__(self) -> tuple:
        return ("CA Public Key", self.value.get_fingerprint())

    def validate(self) -> Union[bool, Exception]:
        """
        Validates the contents of the field
        """
        if self.value in [None, False, "", " "]:
            return _EX.InvalidFieldDataException("You need to provide a CA public key")

        if not isinstance(self.value, PublicKey):
            return _EX.InvalidFieldDataException(
                "The CA public key needs to be a sshkey_tools.keys.PublicKey object"
            )

        return True

    @staticmethod
    def decode(data: bytes) -> Tuple[PublicKey, bytes]:
        """
        Decode the certificate field from a byte string
        starting with the encoded public key

        Args:
            data (bytes): The byte string starting with the encoded key

        Returns:
            Tuple[PublicKey, bytes]: The PublicKey field and remainder of the data
        """
        pubkey, data = BytestringField.decode(data)
        pubkey_type = StringField.decode(pubkey)[0]

        return (
            PublicKey.from_string(
                concat_to_string(pubkey_type, " ", b64encode(pubkey))
            ),
            data,
        )

    @classmethod
    def from_object(cls, public_key: PublicKey) -> "CAPublicKeyField":
        """
        Creates a new CAPublicKeyField from a PublicKey object
        """
        return cls(value=public_key)


class SignatureField(CertificateField):
    """
    Creates and contains the signature of the certificate
    """

    DEFAULT = None
    DATA_TYPE = bytes

    # pylint: disable=super-init-not-called
    def __init__(self, private_key: PrivateKey = None, signature: bytes = None):
        self.private_key = private_key
        self.is_signed = False
        self.value = signature

        if signature is not None and ensure_bytestring(signature) not in ("", " "):
            self.is_signed = True

    def __table__(self) -> tuple:
        msg = "No signature"
        if self.is_signed:
            msg = f"Signed with private key {self.private_key.get_fingerprint()}"

        return ("Signature", msg)

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
                "The private key provided is invalid or not supported"
            ) from KeyError

    @staticmethod
    def from_decode(data: bytes) -> Tuple["SignatureField", bytes]:
        """
        Generates a SignatureField child class from the encoded signature

        Args:
            data (bytes): The bytestring containing the encoded signature

        Raises:
            _EX.InvalidDataException: Invalid data

        Returns:
            SignatureField: child of SignatureField
        """
        signature, _ = BytestringField.decode(data)
        signature_type = BytestringField.decode(signature)[0]

        for key, value in SIGNATURE_TYPE_MAP.items():
            if key in signature_type:
                return globals()[value].from_decode(data)

        raise _EX.InvalidDataException("No matching signature type found")

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
        raise _EX.InvalidClassCallException("The base class has no sign function")

    def __bytes__(self) -> None:
        return self.encode(self.value)


class RsaSignatureField(SignatureField):
    """
    Creates and contains the RSA signature from an RSA Private Key
    """

    DEFAULT = None
    DATA_TYPE = bytes

    def __init__(
        self,
        private_key: RsaPrivateKey = None,
        hash_alg: RsaAlgs = RsaAlgs.SHA512,
        signature: bytes = None,
    ):
        super().__init__(private_key, signature)
        self.hash_alg = hash_alg

    @classmethod
    # pylint: disable=arguments-renamed
    def encode(cls, value: bytes, hash_alg: RsaAlgs = RsaAlgs.SHA512) -> bytes:
        """
        Encodes the value to a byte string

        Args:
            signature (bytes): The signature bytes to encode
            hash_alg (RsaAlgs, optional):  The hash algorithm used for the signature.
                                            Defaults to RsaAlgs.SHA256.

        Returns:
            bytes: The encoded byte string
        """
        cls.__validate_type__(value, True)

        return BytestringField.encode(
            StringField.encode(hash_alg.value[0]) + BytestringField.encode(value)
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[Tuple[bytes, bytes], bytes]:
        """
        Decodes a bytestring containing a signature

        Args:
            data (bytes): The bytestring starting with the RSA Signature

        Returns:
            Tuple[ Tuple[ bytes, bytes ], bytes ]: (signature_type, signature), remainder of data
        """
        signature, data = BytestringField.decode(data)

        sig_type, signature = StringField.decode(signature)
        signature, _ = BytestringField.decode(signature)

        return (sig_type, signature), data

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple["RsaSignatureField", bytes]:
        """
        Generates an RsaSignatureField class from the encoded signature

        Args:
            data (bytes): The bytestring containing the encoded signature

        Raises:
            _EX.InvalidDataException: Invalid data

        Returns:
            Tuple[RsaSignatureField, bytes]: RSA Signature field and remainder of data
        """
        signature, data = cls.decode(data)

        return (
            cls(
                private_key=None,
                hash_alg=[alg for alg in RsaAlgs if alg.value[0] == signature[0]][0],
                signature=signature[1],
            ),
            data,
        )

    # pylint: disable=unused-argument
    def sign(self, data: bytes, hash_alg: RsaAlgs = RsaAlgs.SHA512, **kwargs) -> None:
        """
        Signs the provided data with the provided private key

        Args:
            data (bytes): The data to be signed
            hash_alg (RsaAlgs, optional): The RSA algorithm to use for hashing.
                                           Defaults to RsaAlgs.SHA256.
        """
        self.value = self.private_key.sign(data, hash_alg)

        self.hash_alg = hash_alg
        self.is_signed = True

    def __bytes__(self):
        return self.encode(self.value, self.hash_alg)


class DsaSignatureField(SignatureField):
    """
    Creates and contains the DSA signature from an DSA Private Key
    """

    DEFAULT = None
    DATA_TYPE = bytes

    def __init__(
        self, private_key: DsaPrivateKey = None, signature: bytes = None
    ) -> None:
        super().__init__(private_key, signature)

    @classmethod
    def encode(cls, value: bytes):
        """
        Encodes the signature to a byte string

        Args:
            signature (bytes): The signature bytes to encode

        Returns:
            bytes: The encoded byte string
        """
        cls.__validate_type__(value, True)

        r, s = decode_dss_signature(value)

        return BytestringField.encode(
            StringField.encode("ssh-dss")
            + BytestringField.encode(long_to_bytes(r, 20) + long_to_bytes(s, 20))
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
        signature, data = BytestringField.decode(data)

        signature = BytestringField.decode(BytestringField.decode(signature)[1])[0]
        r = bytes_to_long(signature[:20])
        s = bytes_to_long(signature[20:])

        signature = encode_dss_signature(r, s)

        return signature, data

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple["DsaSignatureField", bytes]:
        """
        Creates a signature field class from the encoded signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ DsaSignatureField, bytes ]: signature, remainder of the data
        """
        signature, data = cls.decode(data)

        return cls(private_key=None, signature=signature), data

    # pylint: disable=unused-argument
    def sign(self, data: bytes, **kwargs) -> None:
        """
        Signs the provided data with the provided private key

        Args:
            data (bytes): The data to be signed
        """
        self.value = self.private_key.sign(data)
        self.is_signed = True


class EcdsaSignatureField(SignatureField):
    """
    Creates and contains the ECDSA signature from an ECDSA Private Key
    """

    DEFAULT = None
    DATA_TYPE = bytes

    def __init__(
        self,
        private_key: EcdsaPrivateKey = None,
        signature: bytes = None,
        curve_name: str = None,
    ) -> None:
        super().__init__(private_key, signature)

        if curve_name is None:
            curve_size = self.private_key.public_key.key.curve.key_size
            curve_name = f"ecdsa-sha2-nistp{curve_size}"

        self.curve = curve_name

    @classmethod
    def encode(cls, value: bytes, curve_name: str = None) -> bytes:
        """
        Encodes the signature to a byte string

        Args:
            signature (bytes): The signature bytes to encode
            curve_name (str): The name of the curve used for the signature
                              private key

        Returns:
            bytes: The encoded byte string
        """
        cls.__validate_type__(value, True)

        r, s = decode_dss_signature(value)

        return BytestringField.encode(
            StringField.encode(curve_name)
            + BytestringField.encode(
                MpIntegerField.encode(r) + MpIntegerField.encode(s)
            )
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[Tuple[bytes, bytes], bytes]:
        """
        Decodes a bytestring containing a signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ Tuple[ bytes, bytes ], bytes]: (curve, signature), remainder of the data
        """
        signature, data = BytestringField.decode(data)

        curve, signature = StringField.decode(signature)
        signature, _ = BytestringField.decode(signature)

        r, signature = MpIntegerField.decode(signature)
        s, _ = MpIntegerField.decode(signature)

        signature = encode_dss_signature(r, s)

        return (curve, signature), data

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple["EcdsaSignatureField", bytes]:
        """
        Creates a signature field class from the encoded signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ EcdsaSignatureField , bytes ]: signature, remainder of the data
        """
        signature, data = cls.decode(data)

        return (
            cls(private_key=None, signature=signature[1], curve_name=signature[0]),
            data,
        )

    # pylint: disable=unused-argument
    def sign(self, data: bytes, **kwargs) -> None:
        """
        Signs the provided data with the provided private key

        Args:
            data (bytes): The data to be signed
        """
        self.value = self.private_key.sign(data)
        self.is_signed = True

    def __bytes__(self):
        return self.encode(self.value, self.curve)


class Ed25519SignatureField(SignatureField):
    """
    Creates and contains the ED25519 signature from an ED25519 Private Key
    """

    DEFAULT = None
    DATA_TYPE = bytes

    def __init__(
        self,
        # trunk-ignore(gitleaks/generic-api-key)
        private_key: Ed25519PrivateKey = None,
        signature: bytes = None,
    ) -> None:
        super().__init__(private_key, signature)

    @classmethod
    def encode(cls, value: bytes) -> None:
        """
        Encodes the signature to a byte string

        Args:
            signature (bytes): The signature bytes to encode

        Returns:
            bytes: The encoded byte string
        """
        cls.__validate_type__(value, True)

        return BytestringField.encode(
            StringField.encode("ssh-ed25519") + BytestringField.encode(value)
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
        signature, data = BytestringField.decode(data)

        signature = BytestringField.decode(BytestringField.decode(signature)[1])[0]

        return signature, data

    @classmethod
    def from_decode(cls, data: bytes) -> Tuple["Ed25519SignatureField", bytes]:
        """
        Creates a signature field class from the encoded signature

        Args:
            data (bytes): The bytestring starting with the Signature

        Returns:
            Tuple[ Ed25519SignatureField , bytes ]: signature, remainder of the data
        """
        signature, data = cls.decode(data)

        return cls(private_key=None, signature=signature), data

    # pylint: disable=unused-argument
    def sign(self, data: bytes, **kwargs) -> None:
        """
        Signs the provided data with the provided private key

        Args:
            data (bytes): The data to be signed
            hash_alg (RsaAlgs, optional): The RSA algorithm to use for hashing.
                                           Defaults to RsaAlgs.SHA256.
        """
        self.value = self.private_key.sign(data)
        self.is_signed = True
