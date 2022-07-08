"""Contains classes for OpenSSH Certificates, generation, parsing and signing
    Raises:
        _EX.SSHCertificateException: General error in certificate
        _EX.InvalidCertificateFormatException: An error with the format of the certificate
        _EX.InvalidCertificateFieldException: An invalid field has been added to the certificate
        _EX.NoPrivateKeyException: The certificate contains no private key
        _EX.NotSignedException: The certificate is not signed and cannot be exported

"""
from base64 import b64encode, b64decode
from dataclasses import dataclass
from typing import Union
from enum import Enum
from .keys import (
    PublicKey,
    PrivateKey,
    RsaPublicKey,
    DsaPublicKey,
    EcdsaPublicKey,
    Ed25519PublicKey,
)
from . import fields as _FIELD
from . import exceptions as _EX
from .keys import RsaAlgs
from .utils import join_dicts, concat_to_string, concat_to_bytestring, ensure_string, ensure_bytestring

CERT_TYPES = {
    "ssh-rsa-cert-v01@openssh.com": ("RsaCertificate", "_FIELD.RsaPubkeyField"),
    "rsa-sha2-256-cert-v01@openssh.com": ("RsaCertificate", "_FIELD.RsaPubkeyField"),
    "rsa-sha2-512-cert-v01@openssh.com": ("RsaCertificate", "_FIELD.RsaPubkeyField"),
    "ssh-dss-cert-v01@openssh.com": ("DsaCertificate", "_FIELD.DsaPubkeyField"),
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": (
        "EcdsaCertificate",
        "_FIELD.EcdsaPubkeyField",
    ),
    "ecdsa-sha2-nistp384-cert-v01@openssh.com": (
        "EcdsaCertificate",
        "_FIELD.EcdsaPubkeyField",
    ),
    "ecdsa-sha2-nistp521-cert-v01@openssh.com": (
        "EcdsaCertificate",
        "_FIELD.EcdsaPubkeyField",
    ),
    "ssh-ed25519-cert-v01@openssh.com": (
        "Ed25519Certificate",
        "_FIELD.Ed25519PubkeyField",
    ),
}


@dataclass
class Fieldset:
    def __setattr__(self, name, value):
        field = getattr(self, name, None)
        
        if callable(field) and not isinstance(field, _FIELD.CertificateField):
            if field.__name__ == "factory":
                super().__setattr__(name, field())
                self.__setattr__(name, value)
                return

        if isinstance(field, type) and getattr(value, '__name__', '') != 'factory':
            super().__setattr__(name, field(value))
            return
        
        if getattr(value, '__name__', '') != 'factory':
            field.value = value
            super().__setattr__(name, field)
    
    def replace_field(self, name: str, value: Union[_FIELD.CertificateField, type]):
        super(Fieldset, self).__setattr__(name, value)
 
    def get(self, name: str, default=None):
        field = getattr(self, name, default)
        if field:
            if isinstance(field, type):
                return field.DEFAULT
            return field.value
        return field
    
    def getattrs(self) -> tuple:
        return tuple(k for k in self.__dict__.keys() if not k.startswith('_'))
    
    def validate(self):
        ex = []
        for key in self.getattrs():
            if not getattr(self, key).validate():
                list([
                    ex.append(f"{type(x)}: {str(x)}") for x in getattr(self, key).exception
                    if isinstance(x, Exception)
                ])
                
        return True if len(ex) == 0 else ex

@dataclass
class CertificateHeader(Fieldset):
    public_key: _FIELD.PublicKeyField = _FIELD.PublicKeyField.factory
    pubkey_type: _FIELD.PubkeyTypeField = _FIELD.PubkeyTypeField.factory
    nonce: _FIELD.NonceField = _FIELD.NonceField.factory

    def __bytes__(self):
        return concat_to_bytestring(
            bytes(self.pubkey_type),
            bytes(self.nonce),
            bytes(self.public_key)
        )
    
@dataclass
class CertificateFields(Fieldset):
    serial: _FIELD.SerialField = _FIELD.SerialField.factory
    cert_type: _FIELD.CertificateTypeField = _FIELD.CertificateTypeField.factory
    key_id: _FIELD.KeyIdField = _FIELD.KeyIdField.factory
    principals: _FIELD.PrincipalsField = _FIELD.PrincipalsField.factory
    valid_after: _FIELD.ValidAfterField = _FIELD.ValidAfterField.factory
    valid_before: _FIELD.ValidBeforeField = _FIELD.ValidBeforeField.factory
    critical_options: _FIELD.CriticalOptionsField = _FIELD.CriticalOptionsField.factory
    extensions: _FIELD.ExtensionsField = _FIELD.ExtensionsField.factory
    
    def __bytes__(self):
        return concat_to_bytestring(
            bytes(self.serial),
            bytes(self.cert_type),
            bytes(self.key_id),
            bytes(self.principals),
            bytes(self.valid_after),
            bytes(self.valid_before),
            bytes(self.critical_options),
            bytes(self.extensions)
        )

@dataclass
class CertificateFooter(Fieldset):
    reserved: _FIELD.ReservedField = _FIELD.ReservedField.factory
    ca_pubkey: _FIELD.CAPublicKeyField = _FIELD.CAPublicKeyField.factory
    signature: _FIELD.SignatureField = _FIELD.SignatureField.factory
    
    def __bytes__(self):
        return concat_to_bytestring(
            bytes(self.reserved),
            bytes(self.ca_pubkey)
        )

class SSHCertificate:
    """
    General class for SSH Certificates, used for loading and parsing.
    To create new certificates, use the respective keytype classes
    or the from_public_key classmethod
    """
    DEFAULT_KEY_TYPE = 'none@openssh.com'
    def __init__(
        self,
        subject_pubkey: PublicKey = None,
        ca_privkey: PrivateKey = None,
        fields: CertificateFields = CertificateFields,
        header: CertificateHeader = CertificateHeader,
        footer: CertificateFooter = CertificateFooter
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
                'public_key',
                _FIELD.PublicKeyField.from_object(subject_pubkey)
            )
            
        if isinstance(footer, type) and ca_privkey is not None:
            self.footer.ca_pubkey = ca_privkey.public_key
            self.footer.replace_field(
                'signature',
                _FIELD.SignatureField.from_object(ca_privkey)
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
            bytes(self.footer.signature)
        )

    @classmethod
    def create(
        cls,
        subject_pubkey: PublicKey = None,
        ca_privkey: PrivateKey = None,
        fields: CertificateFields = CertificateFields
    ):
        cert_class = subject_pubkey.__class__.__name__.replace("PublicKey", "Certificate")
        return globals()[cert_class](
            subject_pubkey=subject_pubkey,
            ca_privkey=ca_privkey,
            fields=fields
        )
        
    @classmethod
    def decode(cls,cert_data: Union[str, bytes]):
        pass
    
    def get(self, field: str):
        if field in (
            self.header.getattrs() +
            self.fields.getattrs() +
            self.footer.getattrs()
        ):
            return (
                self.fields.get(field, False) or
                self.header.get(field, False) or
                self.footer.get(field, False)
            )

        raise _EX.InvalidCertificateFieldException(f"Unknown field {field}")
        
    def set(self, field: str, value):
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
        
    def can_sign(self) -> bool:
        valid_header = self.header.validate()
        valid_fields = self.fields.validate()
        check_keys = (
            True if isinstance(self.get('ca_pubkey'), PublicKey) and 
            isinstance(self.footer.signature.private_key, PrivateKey)
            else [
                _EX.SignatureNotPossibleException('No CA Public/Private key is loaded')
            ]
        )
        
        if (valid_header, valid_fields, check_keys) != (True, True, True):
            raise _EX.SignatureNotPossibleException(
                "\n".join(
                    valid_header if valid_header != True else [] +
                    valid_fields if valid_fields != True else [] +
                    check_keys if check_keys != True else []
                )
            )
            
        return True
    
    def get_signable(self) -> bytes:
        """
        Retrieves the signable data for the certificate in byte form
        """
        return concat_to_bytestring(
            bytes(self.header),
            bytes(self.fields),
            bytes(self.footer)
        )

    def sign(self) -> bool:
        if self.can_sign():
            self.footer.signature.sign(
                data=self.get_signable()
            )

            return True
        
    def to_string(self, comment: str = '', encoding: str = 'utf-8'):
        return concat_to_string(
            self.header.get('pubkey_type'),
            " ",
            b64encode(bytes(self)),
            " ",
            comment if comment else "",
            encoding=encoding
        )
    
    def to_file(self, filename: str):
        with open(filename, 'w') as f:
            f.write(self.to_string())
            
class RsaCertificate(SSHCertificate):
    DEFAULT_KEY_TYPE = 'rsa-sha2-512-cert-v01@openssh.com'
    
class DsaCertificate(SSHCertificate):
    DEFAULT_KEY_TYPE = 'ssh-dss-cert-v01@openssh.com'

class EcdsaCertificate(SSHCertificate):
    DEFAULT_KEY_TYPE = 'ecdsa-sha2-nistp[curve_size]-cert-v01@openssh.com'
    
    def __post_init__(self):
        """Set the key name from the public key curve size"""
        self.header.pubkey_type = self.header.get("pubkey_type").replace(
            "[curve_size]",
            str(self.header.public_key.value.key.curve.key_size)
        )

class Ed25519Certificate(SSHCertificate):
    DEFAULT_KEY_TYPE = 'ssh-ed25519-cert-v01@openssh.com'