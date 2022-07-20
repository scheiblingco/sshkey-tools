# pylint: disable=super-with-arguments
"""
Contains classes for OpenSSH Certificates, generation, parsing and signing
Raises:
    _EX.SSHCertificateException: General error in certificate
    _EX.InvalidCertificateFormatException: An error with the format of the certificate
    _EX.InvalidCertificateFieldException: An invalid field has been added to the certificate
    _EX.NoPrivateKeyException: The certificate contains no private key
    _EX.NotSignedException: The certificate is not signed and cannot be exported
"""
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Tuple, Union

from prettytable import PrettyTable

from . import exceptions as _EX
from . import fields as _FIELD
from .keys import PrivateKey, PublicKey
from .utils import concat_to_bytestring, concat_to_string, ensure_bytestring

CERT_TYPES = {
    "ssh-rsa-cert-v01@openssh.com": ("RsaCertificate", "RsaPubkeyField"),
    "rsa-sha2-256-cert-v01@openssh.com": ("RsaCertificate", "RsaPubkeyField"),
    "rsa-sha2-512-cert-v01@openssh.com": ("RsaCertificate", "RsaPubkeyField"),
    "ssh-dss-cert-v01@openssh.com": ("DsaCertificate", "DsaPubkeyField"),
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": (
        "EcdsaCertificate",
        "EcdsaPubkeyField",
    ),
    "ecdsa-sha2-nistp384-cert-v01@openssh.com": (
        "EcdsaCertificate",
        "EcdsaPubkeyField",
    ),
    "ecdsa-sha2-nistp521-cert-v01@openssh.com": (
        "EcdsaCertificate",
        "EcdsaPubkeyField",
    ),
    "ssh-ed25519-cert-v01@openssh.com": (
        "Ed25519Certificate",
        "Ed25519PubkeyField",
    ),
}


@dataclass
class Fieldset:
    """Set of fields for SSHCertificate class"""

    DECODE_ORDER = []

    def __table__(self):
        return [getattr(self, item).__table__() for item in self.getattrs()]

    def __setattr__(self, name, value):
        field = getattr(self, name, None)

        if isinstance(value, _FIELD.CertificateField):
            self.replace_field(name, value)
            return

        if callable(field) and not isinstance(field, _FIELD.CertificateField):
            if field.__name__ == "factory":
                super().__setattr__(name, field())
                self.__setattr__(name, value)
                return

        if isinstance(field, type) and getattr(value, "__name__", "") != "factory":
            super().__setattr__(name, field(value))
            return

        if getattr(value, "__name__", "") != "factory":
            field.value = value
            super().__setattr__(name, field)

    def replace_field(self, name: str, value: Union[_FIELD.CertificateField, type]):
        """Completely replace field instead of just setting value (original __setattr__ behaviour)

        Args:
            name (str): The field to replace
            value (Union[_FIELD.CertificateField, type]): The CertificateField
            subclass or instance to replace with
        """
        super(Fieldset, self).__setattr__(name, value)

    def get(self, name: str, default=None):
        """Get field contents

        Args:
            name (str): Field name
            default (_type_, optional): The default value to return in case the
            field is not set. Defaults to None.

        Returns:
            mixed: The contents of the field
        """
        field = getattr(self, name, default)
        if field:
            if isinstance(field, type):
                return field.DEFAULT
            return field.value
        return field

    def getattrs(self) -> tuple:
        """Get all class attributes

        Returns:
            tuple: All public class attributes
        """
        # pylint: disable=consider-iterating-dictionary
        return tuple(att for att in self.__dict__.keys() if not att.startswith("_"))

    def validate(self):
        """Validate all fields to ensure the data is correct

        Returns:
            bool: True if valid, else exception
        """
        ex = []
        for key in self.getattrs():
            if not getattr(self, key).validate():
                list(
                    ex.append(f"{type(x)}: {str(x)}")
                    for x in getattr(self, key).exception
                    if isinstance(x, Exception)
                )

        return True if len(ex) == 0 else ex

    @classmethod
    def decode(cls, data: bytes) -> Tuple["Fieldset", bytes]:
        """Decode the certificate field data from a stream of bytes

        Returns:
            Tuple[Fieldset, bytes]: A tuple with the fieldset (Header, Fields or Footer)
            and the remaining bytes.
        """
        cl_instance = cls()
        for item in cls.DECODE_ORDER:
            decoded, data = getattr(cl_instance, item).from_decode(data)
            setattr(cl_instance, item, decoded)

        return cl_instance, data


@dataclass
class CertificateHeader(Fieldset):
    """Header fields for the certificate"""

    public_key: _FIELD.PublicKeyField = _FIELD.PublicKeyField.factory
    pubkey_type: _FIELD.PubkeyTypeField = _FIELD.PubkeyTypeField.factory
    nonce: _FIELD.NonceField = _FIELD.NonceField.factory

    DECODE_ORDER = ["pubkey_type", "nonce"]

    def __bytes__(self):
        return concat_to_bytestring(
            bytes(self.pubkey_type), bytes(self.nonce), bytes(self.public_key)
        )

    @classmethod
    def decode(cls, data: bytes) -> Tuple["CertificateHeader", bytes]:
        cl_instance, data = super().decode(data)

        target_class = CERT_TYPES[cl_instance.get("pubkey_type")]

        public_key, data = getattr(_FIELD, target_class[1]).from_decode(data)
        cl_instance.public_key = public_key

        return cl_instance, data


@dataclass
# pylint: disable=too-many-instance-attributes
class CertificateFields(Fieldset):
    """Information fields for the certificate"""

    serial: _FIELD.SerialField = _FIELD.SerialField.factory
    cert_type: _FIELD.CertificateTypeField = _FIELD.CertificateTypeField.factory
    key_id: _FIELD.KeyIdField = _FIELD.KeyIdField.factory
    principals: _FIELD.PrincipalsField = _FIELD.PrincipalsField.factory
    valid_after: _FIELD.ValidAfterField = _FIELD.ValidAfterField.factory
    valid_before: _FIELD.ValidBeforeField = _FIELD.ValidBeforeField.factory
    critical_options: _FIELD.CriticalOptionsField = _FIELD.CriticalOptionsField.factory
    extensions: _FIELD.ExtensionsField = _FIELD.ExtensionsField.factory

    DECODE_ORDER = [
        "serial",
        "cert_type",
        "key_id",
        "principals",
        "valid_after",
        "valid_before",
        "critical_options",
        "extensions",
    ]

    def __bytes__(self):
        return concat_to_bytestring(
            bytes(self.serial),
            bytes(self.cert_type),
            bytes(self.key_id),
            bytes(self.principals),
            bytes(self.valid_after),
            bytes(self.valid_before),
            bytes(self.critical_options),
            bytes(self.extensions),
        )


@dataclass
class CertificateFooter(Fieldset):
    """Footer fields and signature for the certificate"""

    reserved: _FIELD.ReservedField = _FIELD.ReservedField.factory
    ca_pubkey: _FIELD.CAPublicKeyField = _FIELD.CAPublicKeyField.factory
    signature: _FIELD.SignatureField = _FIELD.SignatureField.factory

    DECODE_ORDER = ["reserved", "ca_pubkey", "signature"]

    def __bytes__(self):
        return concat_to_bytestring(bytes(self.reserved), bytes(self.ca_pubkey))


class SSHCertificate:
    """
    General class for SSH Certificates, used for loading and parsing.
    To create new certificates, use the respective keytype classes
    or the from_public_key classmethod
    """

    DEFAULT_KEY_TYPE = "none@openssh.com"
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        subject_pubkey: PublicKey = None,
        ca_privkey: PrivateKey = None,
        fields: CertificateFields = CertificateFields,
        header: CertificateHeader = CertificateHeader,
        footer: CertificateFooter = CertificateFooter,
    ):
        if self.__class__.__name__ == "SSHCertificate":
            raise _EX.InvalidClassCallException(
                "You cannot instantiate SSHCertificate directly. Use \n"
                + "one of the child classes, or call via decode, create \n"
                + "or one of the from_-classmethods"
            )

        self.fields = fields() if isinstance(fields, type) else fields
        self.header = header() if isinstance(header, type) else header
        self.footer = footer() if isinstance(footer, type) else footer

        if isinstance(header, type) and subject_pubkey is not None:
            self.header.pubkey_type = self.DEFAULT_KEY_TYPE
            self.header.replace_field(
                "public_key", _FIELD.PublicKeyField.from_object(subject_pubkey)
            )

        if isinstance(footer, type) and ca_privkey is not None:
            self.footer.ca_pubkey = ca_privkey.public_key
            self.footer.replace_field(
                "signature", _FIELD.SignatureField.from_object(ca_privkey)
            )

        self.__post_init__()

    def __post_init__(self):
        """Extensible function for post-initialization for child classes"""

    def __bytes__(self):
        if not self.footer.signature.is_signed:
            raise _EX.InvalidCertificateFormatException(
                "Failed exporting certificate: Certificate is not signed"
            )

        return concat_to_bytestring(
            bytes(self.header),
            bytes(self.fields),
            bytes(self.footer),
            bytes(self.footer.signature),
        )

    def __str__(self) -> str:
        table = PrettyTable(["Field", "Value"])

        for item in (self.header, self.fields, self.footer):
            for row in item.__table__():
                table.add_row(row)

        return str(table)

    @classmethod
    def create(
        cls,
        subject_pubkey: PublicKey = None,
        ca_privkey: PrivateKey = None,
        fields: CertificateFields = CertificateFields,
        header: CertificateHeader = CertificateHeader,
        footer: CertificateFooter = CertificateFooter,
    ) -> "SSHCertificate":
        """
        Creates a new certificate from the given parameters.

        Args:
            subject_pubkey (PublicKey, optional): The subject public key. Defaults to None.
            ca_privkey (PrivateKey, optional): The CA private key. Defaults to None.
            fields (CertificateFields, optional): The CertificateFields object containing the
                body fields. Defaults to blank CertificateFields.
            header (CertificateHeader, optional): The certificate header.
                Defaults to new CertificateHeader.
            footer (CertificateFooter, optional): The certificate footer.
                Defaults to new CertificateFooter.

        Returns:
            SSHCertificate: A SSHCertificate subclass depending on the type of subject_pubkey
        """
        cert_class = subject_pubkey.__class__.__name__.replace(
            "PublicKey", "Certificate"
        )
        return globals()[cert_class](
            subject_pubkey=subject_pubkey,
            ca_privkey=ca_privkey,
            fields=fields,
            header=header,
            footer=footer,
        )

    @classmethod
    def decode(cls, data: bytes) -> "SSHCertificate":
        """
        Decode an existing certificate and import it into a new object

        Args:
            data (bytes): The certificate bytes, base64 decoded middle part of the certificate

        Returns:
            SSHCertificate: SSHCertificate child class
        """
        cert_header, data = CertificateHeader.decode(data)
        cert_fields, data = CertificateFields.decode(data)
        cert_footer, data = CertificateFooter.decode(data)

        return cls(header=cert_header, fields=cert_fields, footer=cert_footer)

    @classmethod
    def from_bytes(cls, cert_bytes: bytes):
        """
        Loads an existing certificate from the byte value.

        Args:
            cert_bytes (bytes): Certificate bytes, base64 decoded middle part of the certificate

        Returns:
            SSHCertificate: SSHCertificate child class
        """
        cert_type, _ = _FIELD.StringField.decode(cert_bytes)
        target_class = CERT_TYPES[cert_type]
        return globals()[target_class[0]].decode(cert_bytes)

    @classmethod
    def from_string(cls, cert_str: Union[str, bytes], encoding: str = "utf-8"):
        """
        Loads an existing certificate from a string in the format
        [certificate-type] [base64-encoded-certificate] [optional-comment]

        Args:
            cert_str (str): The string containing the certificate
            encoding (str, optional): The encoding of the string. Defaults to 'utf-8'.

        Returns:
            SSHCertificate: SSHCertificate child class
        """
        cert_str = ensure_bytestring(cert_str, encoding)

        certificate = b64decode(cert_str.split(b" ")[1])
        return cls.from_bytes(cert_bytes=certificate)

    @classmethod
    def from_file(cls, path: str, encoding: str = "utf-8"):
        """
        Loads an existing certificate from a file

        Args:
            path (str): The path to the certificate file
            encoding (str, optional): Encoding of the file. Defaults to 'utf-8'.

        Returns:
            SSHCertificate: SSHCertificate child class
        """
        with open(path, "r", encoding=encoding) as file:
            return cls.from_string(file.read())

    def get(self, field: str):
        """
        Fetch a field from any of the sections of the certificate.

        Args:
            field (str): The field name to fetch

        Raises:
            _EX.InvalidCertificateFieldException: Invalid field name provided

        Returns:
            mixed: The certificate field contents
        """
        if field in (
            self.header.getattrs() + self.fields.getattrs() + self.footer.getattrs()
        ):
            return (
                self.fields.get(field, False)
                or self.header.get(field, False)
                or self.footer.get(field, False)
            )

        raise _EX.InvalidCertificateFieldException(f"Unknown field {field}")

    def set(self, field: str, value) -> None:
        """
        Set a field in any of the sections of the certificate.

        Args:
            field (str): The field name to set
            value (mixed): The value to set the field to

        Raises:
            _EX.InvalidCertificateFieldException: Invalid field name provided

        Returns:
            mixed: The certificate field contents
        """
        if self.fields.get(field, False):
            setattr(self.fields, field, value)
            return

        if self.header.get(field, False):
            setattr(self.header, field, value)
            return

        if self.footer.get(field, False):
            setattr(self.footer, field, value)
            return

        raise _EX.InvalidCertificateFieldException(f"Unknown field {field}")

    def replace_ca(self, ca_privkey: PrivateKey):
        """
        Replace the certificate authority private key with a new one.

        Args:
            ca_privkey (PrivateKey): The new CA private key
        """
        self.footer.ca_pubkey = ca_privkey.public_key
        self.footer.replace_field(
            "signature", _FIELD.SignatureField.from_object(ca_privkey)
        )

    def can_sign(self) -> bool:
        """
        Check if the certificate can be signed in its current state.

        Raises:
            _EX.SignatureNotPossibleException: Exception if the certificate cannot be signed

        Returns:
            bool: True if the certificate can be signed
        """
        valid_header = self.header.validate()
        valid_fields = self.fields.validate()
        check_keys = (
            True
            if isinstance(self.get("ca_pubkey"), PublicKey)
            and isinstance(self.footer.signature.private_key, PrivateKey)
            else [
                _EX.SignatureNotPossibleException("No CA Public/Private key is loaded")
            ]
        )

        if (valid_header, valid_fields, check_keys) != (True, True, True):
            exceptions = []
            exceptions += valid_header if not isinstance(valid_header, bool) else []
            exceptions += valid_fields if not isinstance(valid_fields, bool) else []
            exceptions += check_keys if not isinstance(check_keys, bool) else []
            raise _EX.SignatureNotPossibleException(
                "\n".join([str(e) for e in exceptions])
            )

        return True

    def get_signable(self) -> bytes:
        """
        Retrieves the signable data for the certificate in byte form
        """
        return concat_to_bytestring(
            bytes(self.header), bytes(self.fields), bytes(self.footer)
        )

    def sign(self) -> bool:
        """Sign the certificate

        Raises:
            _EX.NotSignedException: The certificate could not be signed

        Returns:
            bool: Whether successful
        """
        if self.can_sign():
            self.footer.signature.sign(data=self.get_signable())

            return True
        raise _EX.NotSignedException("There was an error while signing the certificate")

    def verify(
        self, public_key: PublicKey = None, raise_on_error: bool = False
    ) -> bool:
        """Verify the signature on the certificate to make sure the data is not corrupted,
           and that the signature comes from the given public key or the key included in the
           certificate (insecure, useful for testing only)

        Args:
            public_key (PublicKey, optional): The public key to use for verification
            raise_on_error (bool, default False): Raise an exception if the certificate is invalid

        Raises:
            _EX.InvalidSignatureException: The signature is invalid
        """
        if not public_key:
            public_key = self.get("ca_pubkey")

        try:
            public_key.verify(self.get_signable(), self.footer.get("signature"))
        except _EX.InvalidSignatureException as exception:
            if raise_on_error:
                raise exception
            return False

        return True

    def to_string(self, comment: str = "", encoding: str = "utf-8"):
        """Export the certificate to a string

        Args:
            comment (str, optional): Comment to append to the certificate. Defaults to "".
            encoding (str, optional): Which encoding to use for the string. Defaults to "utf-8".

        Returns:
            str: The certificate data, base64-encoded and in string format
        """
        return concat_to_string(
            self.header.get("pubkey_type"),
            " ",
            b64encode(bytes(self)),
            " ",
            comment if comment else "",
            encoding=encoding,
        )

    def to_file(self, filename: str, encoding: str = "utf-8"):
        """Export certificate to file

        Args:
            filename (str): The filename to write to
            encoding (str, optional): The encoding to use for the file/string. Defaults to "utf-8".
        """
        with open(filename, "w", encoding=encoding) as file:
            file.write(self.to_string())


class RsaCertificate(SSHCertificate):
    """The RSA Certificate class"""

    DEFAULT_KEY_TYPE = "rsa-sha2-512-cert-v01@openssh.com"


class DsaCertificate(SSHCertificate):
    """The DSA Certificate class"""

    DEFAULT_KEY_TYPE = "ssh-dss-cert-v01@openssh.com"


class EcdsaCertificate(SSHCertificate):
    """The ECDSA certificate class"""

    DEFAULT_KEY_TYPE = "ecdsa-sha2-nistp[curve_size]-cert-v01@openssh.com"

    def __post_init__(self):
        """Set the key name from the public key curve size"""
        self.header.pubkey_type = self.header.get("pubkey_type").replace(
            "[curve_size]", str(self.header.public_key.value.key.curve.key_size)
        )


class Ed25519Certificate(SSHCertificate):
    """The ED25519 certificate class"""

    DEFAULT_KEY_TYPE = "ssh-ed25519-cert-v01@openssh.com"
