from enum import Enum
from datetime import datetime, timedelta
from base64 import b64encode, b64decode
from re import X
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
from typing import Tuple

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

PUBKEY_FIELDS = {
    
}

CERT_TYPES = {
    'ssh-rsa-cert-v01@openssh.com': ('RSACertificate', '_FIELD.RSAPubkeyField'),
    'rsa-sha2-256-cert-v01@openssh.com': ('RSACertificate', '_FIELD.RSAPubkeyField'),
    'rsa-sha2-512-cert-v01@openssh.com': ('RSACertificate', '_FIELD.RSAPubkeyField'),
    'ssh-dss-cert-v01@openssh.com': ('DSACertificate', '_FIELD.DSAPubkeyField'),
    'ecdsa-sha2-nistp256-cert-v01@openssh.com': ('ECDSACertificate', '_FIELD.ECDSAPubkeyField'),
    'ecdsa-sha2-nistp384-cert-v01@openssh.com': ('ECDSACertificate', '_FIELD.ECDSAPubkeyField'),
    'ecdsa-sha2-nistp521-cert-v01@openssh.com': ('ECDSACertificate', '_FIELD.ECDSAPubkeyField'),
    'ssh-ed25519-cert-v01@openssh.com': ('ED25519Certificate', '_FIELD.ED25519PubkeyField'),
}

class SSHCertificate:
    def __init__(
        self,
        subject_pubkey: PublicKey = None,
        ca_privkey: PrivateKey = None,
        decoded: dict = None,
        **kwargs
    ) -> None:

        if decoded is not None:
            self.signature = decoded.pop('signature')
            self.signature_pubkey = decoded.pop('ca_pubkey')
            
            self.header = {
                'pubkey_type': decoded.pop('pubkey_type'),
                'nonce': decoded.pop('nonce'),
                'public_key': decoded.pop('public_key')
            }

            self.fields = decoded
            
            return

        if subject_pubkey is None:
            raise _EX.SSHCertificateException(
                "The subject public key is required"
            )

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
    
    def __str__(self):
        principals = '\n' + '\n'.join(
            ''.join([' ']*20) + (
                x.decode('utf-8') if isinstance(x, bytes) else x
            ) for x in self.fields['principals'].value
        ) if len(self.fields['principals'].value) > 0 else 'none'
        
        critical = '\n' + '\n'.join(
            ''.join([' ']*20) + (
                x.decode('utf-8') if isinstance(x, bytes) else x
            ) for x in self.fields['critical_options'].value
        ) if len(self.fields['critical_options'].value) > 0 else 'none'
        
        extensions = '\n' + '\n'.join(
            ''.join([' ']*20) + (
                x.decode('utf-8') if isinstance(x, bytes) else x
            ) for x in self.fields['extensions'].value
        ) if len(self.fields['extensions'].value) > 0 else 'none'
        
        signature_val = b64encode(self.signature.value).decode('utf-8') if isinstance(
            self.signature.value,
            bytes
        ) else "Not signed"
        
        return f'''
Pubkey Type:        {self.header['pubkey_type'].value}
Public Key:         {self.header['public_key'].value}
CA Public Key:      {self.signature_pubkey.value}
Nonce:              {self.header['nonce'].value}
Certificate Type:   {'User' if self.fields['cert_type'].value == 1 else 'Host'}
Valid After:        {self.fields['valid_after'].value.strftime('%Y-%m-%d %H:%M:%S')}
Valid Until:        {self.fields['valid_before'].value.strftime('%Y-%m-%d %H:%M:%S')}
Principals:         {principals}
Critical options:   {critical}
Extensions:         {extensions}
Signature:          {signature_val}
        '''
     
    @staticmethod
    def decode(cert_bytes: bytes, pubkey_field: _FIELD.PublicKeyField) -> 'SSHCertificate':       
        decode_fields = {
            'pubkey_type': _FIELD.PubkeyTypeField,
            'nonce': _FIELD.NonceField,
            'public_key': pubkey_field
        } | CERTIFICATE_FIELDS | {
            'reserved': _FIELD.ReservedField,
            'ca_pubkey': _FIELD.CAPublicKeyField,
            'signature': _FIELD.SignatureField
        }
        
        cert = {}
        
        # Decode everything up to ca pubkey and signature
        for item in decode_fields.keys():
            cert[item], cert_bytes = decode_fields[item].from_decode(cert_bytes)

        if cert_bytes != b'':
            raise _EX.InvalidCertificateFormatException(
                "The certificate has additional data after everything has been extracted"
            )
            
        pubkey_type = cert['pubkey_type'].value
        if isinstance(pubkey_type, bytes):
            pubkey_type = pubkey_type.decode('utf-8')
        
        cert_type = CERT_TYPES[pubkey_type]
        
        return globals()[cert_type[0]](
            subject_pubkey=cert['public_key'].value,
            decoded=cert
        )

    @classmethod
    def from_bytes(cls, cert_bytes: bytes):
        cert_type, _ = _FIELD.StringField.decode(cert_bytes)
        target_class = CERT_TYPES[cert_type.decode('utf-8')]
        return globals()[target_class[0]].decode(cert_bytes)

    @classmethod
    def from_string(cls, cert_str: str, encoding: str = 'utf-8'):
        certificate = b64decode(
            cert_str.split(' ')[1]
        )
        return cls.from_bytes(
            cert_bytes=certificate
        )
        
    @classmethod
    def from_file(cls, path: str, encoding: str = 'utf-8'):
        return cls.from_string(
            open(path, 'r').read()
        )
       
    def set_type(self, pubkey_type: str):
        if not getattr(self.header['pubkey_type'], 'value', False):
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
        
        if self.signature.can_sign() is True and can_sign:
            return True
        
        for item in self.fields.values():
            if isinstance(item, Exception):
                raise item 
        
        raise _EX.NoPrivateKeyException(
            "The certificate cannot be signed, the private key is not loaded"
        )


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
        ca_privkey: PrivateKey = None,
        rsa_alg: RSA_ALGS = RSA_ALGS.SHA512,
        **kwargs,
    ):
            
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.rsa_alg = rsa_alg
        self.set_type(f'{rsa_alg.value[0]}-cert-v01@openssh.com')
        
    @classmethod
    def decode(cls, cert_bytes: bytes) -> 'SSHCertificate':
        return super().decode(
            cert_bytes,
            _FIELD.RSAPubkeyField
        )

class DSACertificate(SSHCertificate):
    def __init__(
        self,
        subject_pubkey: DSAPublicKey,
        ca_privkey: PrivateKey = None,
        **kwargs
    ):
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.set_type('ssh-dss-cert-v01@openssh.com')
        
    @classmethod
    def decode(cls, cert_bytes: bytes) -> 'SSHCertificate':
        return super().decode(
            cert_bytes,
            _FIELD.DSAPubkeyField
        )

class ECDSACertificate(SSHCertificate):
    def __init__(
        self,
        subject_pubkey: ECDSAPublicKey,
        ca_privkey: PrivateKey = None,
        **kwargs
    ):
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.set_type(
            f'ecdsa-sha2-nistp{subject_pubkey.key.curve.key_size}-cert-v01@openssh.com'
        )
        
    @classmethod
    def decode(cls, cert_bytes: bytes) -> 'SSHCertificate':
        return super().decode(
            cert_bytes,
            _FIELD.ECDSAPubkeyField
        )

class ED25519Certificate(SSHCertificate):
    def __init__(
        self,
        subject_pubkey: ED25519PublicKey,
        ca_privkey: PrivateKey = None,
        **kwargs
    ):
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.set_type(
            'ssh-ed25519-cert-v01@openssh.com'
        )

    @classmethod
    def decode(cls, cert_bytes: bytes) -> 'SSHCertificate':
        return super().decode(
            cert_bytes,
            _FIELD.ED25519PubkeyField
        )
    