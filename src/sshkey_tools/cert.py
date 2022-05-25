"""Contains classes for OpenSSH Certificates, generation, parsing and signing
    Raises:
        _EX.SSHCertificateException: General error in certificate
        _EX.InvalidCertificateFormatException: An error with the format of the certificate
        _EX.InvalidCertificateFieldException: An invalid field has been added to the certificate
        _EX.NoPrivateKeyException: The certificate contains no private key
        _EX.NotSignedException: The certificate is not signed and cannot be exported

"""
from base64 import b64encode, b64decode
from typing import Union
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
from .keys import RsaAlgs

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
    """
    General class for SSH Certificates, used for loading and parsing.
    To create new certificates, use the respective keytype classes
    or the from_public_key classmethod
    """
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
            ''.join([' ']*32) + (
                x.decode('utf-8') if isinstance(x, bytes) else x
            ) for x in self.fields['principals'].value
        ) if len(self.fields['principals'].value) > 0 else 'none'

        critical = '\n' + '\n'.join(
            ''.join([' ']*32) + (
                x.decode('utf-8') if isinstance(x, bytes) else x
            ) for x in self.fields['critical_options'].value
        ) if len(self.fields['critical_options'].value) > 0 else 'none'

        extensions = '\n' + '\n'.join(
            ''.join([' ']*32) + (
                x.decode('utf-8') if isinstance(x, bytes) else x
            ) for x in self.fields['extensions'].value
        ) if len(self.fields['extensions'].value) > 0 else 'none'

        signature_val = b64encode(self.signature.value).decode('utf-8') if isinstance(
            self.signature.value,
            bytes
        ) else "Not signed"

        return f'''
        Certificate:
            Pubkey Type:        {self.header['pubkey_type'].value}
            Public Key:         {str(self.header['public_key'])}
            CA Public Key:      {str(self.signature_pubkey)}
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
    def decode(cert_bytes: bytes, pubkey_class: _FIELD.PublicKeyField = None) -> 'SSHCertificate':
        """
        Decode an existing certificate and import it into a new object

        Args:
            cert_bytes (bytes): The certificate bytes, base64 decoded middle part of the certificate
            pubkey_field (_FIELD.PublicKeyField): Instance of the PublicKeyField class, only needs
                to be set if it can't be detected automatically

        Raises:
            _EX.InvalidCertificateFormatException: Invalid or unknown certificate format

        Returns:
            SSHCertificate: SSHCertificate child class
        """
        if pubkey_class is None:
            cert_type = _FIELD.StringField.decode(cert_bytes)[0].encode('utf-8')
            pubkey_class = CERT_TYPES.get(cert_type, False)

        if pubkey_class is False:
            raise _EX.InvalidCertificateFormatException(
                "Could not determine certificate type, please use one " +
                "of the specific classes or specify the pubkey_class"
            )

        decode_fields = {
            'pubkey_type': _FIELD.PubkeyTypeField,
            'nonce': _FIELD.NonceField,
            'public_key': pubkey_class,
        } | CERTIFICATE_FIELDS | {
            'reserved': _FIELD.ReservedField,
            'ca_pubkey': _FIELD.CAPublicKeyField,
            'signature': _FIELD.SignatureField
        }

        cert = {}

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
    def from_public_class(cls, public_key: PublicKey, **kwargs) -> 'SSHCertificate':
        """
        Creates a new certificate from a supplied public key

        Args:
            public_key (PublicKey): The public key for which to create a certificate

        Returns:
            SSHCertificate: SSHCertificate child class
        """
        return globals()[
            public_key.__class__.__name__.replace('PublicKey', 'Certificate')
        ](
            public_key,
            **kwargs
        )

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
        target_class = CERT_TYPES[cert_type.decode('utf-8')]
        return globals()[target_class[0]].decode(cert_bytes)

    @classmethod
    def from_string(cls, cert_str: Union[str, bytes], encoding: str = 'utf-8'):
        """
        Loads an existing certificate from a string in the format
        [certificate-type] [base64-encoded-certificate] [optional-comment]

        Args:
            cert_str (str): The string containing the certificate
            encoding (str, optional): The encoding of the string. Defaults to 'utf-8'.

        Returns:
            SSHCertificate: SSHCertificate child class
        """
        if isinstance(cert_str, str):
            cert_str = cert_str.encode(encoding)

        certificate = b64decode(
            cert_str.split(b' ')[1]
        )
        return cls.from_bytes(
            cert_bytes=certificate
        )

    @classmethod
    def from_file(cls, path: str, encoding: str = 'utf-8'):
        """
        Loads an existing certificate from a file

        Args:
            path (str): The path to the certificate file
            encoding (str, optional): Encoding of the file. Defaults to 'utf-8'.

        Returns:
            SSHCertificate: SSHCertificate child class
        """
        return cls.from_string(
            open(path, 'r', encoding=encoding).read()
        )

    def set_type(self, pubkey_type: str):
        """
        Set the type of the public key if not already set automatically
        The child classes will set this automatically

        Args:
            pubkey_type (str): Public key type, e.g. ssh-rsa-cert-v01@openssh.com
        """
        if not getattr(self.header['pubkey_type'], 'value', False):
            self.header['pubkey_type'] = self.header['pubkey_type'](
                pubkey_type
            )

    def set_opt(self, key: str, value):
        """
        Add information to a field in the certificate

        Args:
            key (str): The key to set
            value (mixed): The new value for the field

        Raises:
            _EX.InvalidCertificateFieldException: Invalid field
        """
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
        """
        Set multiple options at once
        """
        for key, value in kwargs.items():
            self.set_opt(key, value)

    def can_sign(self) -> bool:
        """
        Determine if the certificate is ready to be signed

        Raises:
            ...: Exception from the respective field with error
            _EX.NoPrivateKeyException: Private key is missing from class

        Returns:
            bool: True/False if the certificate can be signed
        """
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
        """
        Gets the signable byte string from the certificate fields

        Returns:
            bytes: The data in the certificate which is signed
        """
        return b''.join([
            bytes(x) for x in
            tuple(self.header.values()) +
            tuple(self.fields.values())
        ]) + bytes(_FIELD.ReservedField()) + bytes(self.signature_pubkey)

    def sign(self):
        """
        Sign the certificate

        Returns:
            SSHCertificate: The signed certificate class
        """
        if self.can_sign():
            self.signature.sign(
                data=self.get_signable_data()
            )

        return self

    def to_bytes(self) -> bytes:
        """
        Export the signed certificate in byte-format

        Raises:
            _EX.NotSignedException: The certificate has not been signed yet

        Returns:
            bytes: The certificate bytes
        """
        if self.signature.is_signed is True:
            return (
                self.get_signable_data() +
                bytes(self.signature)
            )

        raise _EX.NotSignedException("The certificate has not been signed")

    def to_string(self, comment: Union[str, bytes] = None, encoding: str = 'utf-8') -> str:
        """
        Export the signed certificate to a string, ready to be written to file

        Args:
            comment (Union[str, bytes], optional): Comment to add to the string. Defaults to None.
            encoding (str, optional): Encoding to use for the string. Defaults to 'utf-8'.

        Returns:
            str: Certificate string
        """
        return (
            self.header['pubkey_type'].value.encode(encoding) +
            b' ' +
            b64encode(
                self.to_bytes(),
            ) +
            b' ' +
            (comment if comment else b'')
        ).decode('utf-8')

    def to_file(self, path: str, comment: Union[str, bytes] = None, encoding: str = 'utf-8'):
        """
        Saves the certificate to a file

        Args:
            path (str): The path of the file to save to
            comment (Union[str, bytes], optional): Comment to add to the certificate end.
                                                   Defaults to None.
            encoding (str, optional): Encoding for the file. Defaults to 'utf-8'.
        """
        with open(path, 'w', encoding=encoding) as file:
            file.write(
                self.to_string(comment, encoding)
            )

class RSACertificate(SSHCertificate):
    """
    Specific class for RSA Certificates. Inherits from SSHCertificate
    """
    def __init__(
        self,
        subject_pubkey: RSAPublicKey,
        ca_privkey: PrivateKey = None,
        rsa_alg: RsaAlgs = RsaAlgs.SHA512,
        **kwargs,
    ):

        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.rsa_alg = rsa_alg
        self.set_type(f'{rsa_alg.value[0]}-cert-v01@openssh.com')

    @classmethod
    # pylint: disable=arguments-differ
    def decode(cls, cert_bytes: bytes) -> 'SSHCertificate':
        """
        Decode an existing RSA Certificate

        Args:
            cert_bytes (bytes): The base64-decoded bytes for the certificate

        Returns:
            RSACertificate: The decoded certificate
        """
        return super().decode(
            cert_bytes,
            _FIELD.RSAPubkeyField
        )

class DSACertificate(SSHCertificate):
    """
    Specific class for DSA/DSS Certificates. Inherits from SSHCertificate
    """
    def __init__(
        self,
        subject_pubkey: DSAPublicKey,
        ca_privkey: PrivateKey = None,
        **kwargs
    ):
        super().__init__(subject_pubkey, ca_privkey, **kwargs)
        self.set_type('ssh-dss-cert-v01@openssh.com')

    @classmethod
    # pylint: disable=arguments-differ
    def decode(cls, cert_bytes: bytes) -> 'DSACertificate':
        """
        Decode an existing DSA Certificate

        Args:
            cert_bytes (bytes): The base64-decoded bytes for the certificate

        Returns:
            DSACertificate: The decoded certificate
        """
        return super().decode(
            cert_bytes,
            _FIELD.DSAPubkeyField
        )

class ECDSACertificate(SSHCertificate):
    """
    Specific class for ECDSA Certificates. Inherits from SSHCertificate
    """
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
    # pylint: disable=arguments-differ
    def decode(cls, cert_bytes: bytes) -> 'ECDSACertificate':
        """
        Decode an existing ECDSA Certificate

        Args:
            cert_bytes (bytes): The base64-decoded bytes for the certificate

        Returns:
            ECDSACertificate: The decoded certificate
        """
        return super().decode(
            cert_bytes,
            _FIELD.ECDSAPubkeyField
        )

class ED25519Certificate(SSHCertificate):
    """
    Specific class for ED25519 Certificates. Inherits from SSHCertificate
    """
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
    # pylint: disable=arguments-differ
    def decode(cls, cert_bytes: bytes) -> 'ED25519Certificate':
        """
        Decode an existing ED25519 Certificate

        Args:
            cert_bytes (bytes): The base64-decoded bytes for the certificate

        Returns:
            ED25519Certificate: The decoded certificate
        """
        return super().decode(
            cert_bytes,
            _FIELD.ED25519PubkeyField
        )
