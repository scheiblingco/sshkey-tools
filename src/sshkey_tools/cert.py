from enum import Enum
from datetime import datetime, timedelta
from base64 import b64encode
from .keys import (
    PublicKey,
    PrivateKey,
    RSAPublicKey,
    DSAPublicKey,
    ECDSAPublicKey,
    ED25519PublicKey
)
from . import fields as _FIELD
from . import exceptions as _EX
from .keys import RSA_ALGS, STR_OR_BYTES

CERTIFICATE_FIELDS = {
    'serial': _FIELD.SerialField,
    'cert_type': _FIELD.CertificateTypeField,
    'key_id': _FIELD.KeyIDField,
    'principals': _FIELD.PrincipalsField,
    'valid_after': _FIELD.ValidityStartField,
    'valid_before': _FIELD.ValidityEndField,
    'critical_options': _FIELD.CriticalOptionsField,
    'extensions': _FIELD.ExtensionsField
}


class SSHCertificate:
    def __init__(
        self,
        subject_pubkey: PublicKey,
        ca_privkey: PrivateKey,
        **kwargs
    ):

        self.header = {
            'pubkey_type': _FIELD.PubkeyTypeField,
            'nonce': _FIELD.NonceField(),
            'public_key': _FIELD.PublicKeyField.from_object(
                subject_pubkey
            )
        }
        
        self.signature = _FIELD.SignatureField.from_object(
            ca_privkey
        )
        
        self.signature_pubkey = _FIELD.CAPublicKeyField.from_object(
            ca_privkey.public_key
        )

        self.fields = dict(CERTIFICATE_FIELDS)
        self.set_opts(**kwargs)
    
    def set_type(self, pubkey_type: str):
        self.header['pubkey_type'] = self.header['pubkey_type'](
            pubkey_type
        )

    def set_opt(self, key, value):
        if key not in self.fields:
            raise _EX.InvalidCertificateFieldException(
                f'{key} is not a valid certificate field'
            )
        
        try:
            if self.fields[key].value not in [None, False, '', [], ()]:
                self.fields[key].value = value
        except AttributeError:
            self.fields[key] = self.fields[key](value)
        
    def set_opts(self, **kwargs):
        for key, value in kwargs.items():
            self.set_opt(key, value)
            
    def can_sign(self) -> bool:
        can_sign = [
            x.validate() for x in self.fields.values()
        ]
        
        if not can_sign:
            for item in self.fields.values():
                if isinstance(item, Exception):
                    raise item
        
        return can_sign

    def get_signable_data(self) -> bytes:
        return b''.join([
            bytes(x) for x in 
            tuple(self.header.values()) + 
            tuple(self.fields.values())
        ]) + bytes(_FIELD.ReservedField()) + bytes(self.signature_pubkey)

    def sign(self):
        if self.can_sign():
            self.signature.sign(
                data=self.get_signable_data()
            )

    def to_bytes(self) -> bytes:
        if self.signature.is_signed is True:
            return (
                self.get_signable_data() +
                bytes(self.signature)
            )

        raise _EX.NotSignedException("The certificate has not been signed")

    def to_string(self, comment: STR_OR_BYTES = None, encoding: str = 'utf-8') -> str:
        return ( 
            self.header['pubkey_type'].value.encode(encoding) +
            b' ' +
            b64encode(
                self.to_bytes(),
            ) +
            b' ' +
            (comment if comment else b'')
        )

    def to_file(self, path: str, comment: STR_OR_BYTES = None, encoding: str = 'utf-8'):
        with open(path, 'wb') as f:
            f.write(self.to_string(comment, encoding))

class RSACertificate(SSHCertificate):
    def __init__(
        self, 
        subject_pubkey: RSAPublicKey,
        ca_privkey: PrivateKey,
        rsa_alg: RSA_ALGS = RSA_ALGS.SHA512,
        **kwargs,
    ):
            
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.rsa_alg = rsa_alg
        self.set_type(f'{rsa_alg.value[0]}-cert-v01@openssh.com')

class DSACertificate(SSHCertificate):
    def __init__(
        self,
        subject_pubkey: DSAPublicKey,
        ca_privkey: PrivateKey,
        **kwargs
    ):
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.set_type('ssh-dss-cert-v01@openssh.com')

class ECDSACertificate(SSHCertificate):
    def __init__(
        self,
        subject_pubkey: ECDSAPublicKey,
        ca_privkey: PrivateKey,
        **kwargs
    ):
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.set_type(
            f'ecdsa-sha2-nistp{subject_pubkey.key.curve.key_size}-cert-v01@openssh.com'
        )

class ED25519Certificate(SSHCertificate):
    def __init__(
        self,
        subject_pubkey: ED25519PublicKey,
        ca_privkey: PrivateKey,
        **kwargs
    ):
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.set_type(
            'ssh-ed25519-cert-v01@openssh.com'
        )

    