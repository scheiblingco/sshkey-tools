from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization as c_serialization
from cryptography.hazmat.primitives import padding as c_padding
from cryptography.hazmat.primitives import hashes as c_hashes

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey
from cryptography.hazmat.backends.openssl.dsa import _DSAPrivateKey
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey
from cryptography.hazmat.backends.openssl.ed25519 import _Ed25519PrivateKey


from cryptography.hazmat.primitives.serialization import PublicFormat
from base64 import b64encode, b64decode
from enum import Enum
from typing import Union
from . import utils
# from . import certificates as cert

PrivkeyClasses = Union[
            _RSAPrivateKey,
            _DSAPrivateKey,
            _EllipticCurvePrivateKey,
            _Ed25519PrivateKey
            ]


@dataclass
class PublicKeyClass:       
    comment: bytes
    raw_bytes: bytes
    key_type: bytes
 
    def ca_bytes(self):
        return self.raw_bytes

    def subject_bytes(self):
        return utils.decode_string(self.raw_bytes)[1]

@dataclass
class RSAPublicKey(PublicKeyClass):
    comment: bytes
    raw_bytes: bytes
    key_type: bytes
    e: int
    n: int
        
    @classmethod
    def from_bytes(cls, key_data: bytes):
        split = key_data.split(b' ')
        comment = split[2] if split[2] is not None else ''
        raw_bytes = b64decode(split[1])
        
        key_type, data = utils.decode_string(raw_bytes)
        e, data = utils.decode_mpint(data)
        n, data = utils.decode_mpint(data)
        
        return cls(comment, raw_bytes, key_type, e, n)
    
    @classmethod
    def from_numbers(cls, e: int, n: int, comment: utils.StrOrBytes = '', key_type: str = 'ssh-rsa') -> 'RSAPublicKey':
        raw_bytes = utils.encode_string(key_type) + utils.encode_mpint(e) + utils.encode_mpint(n)
        
        return cls(comment, raw_bytes, key_type, e, n)


# def rsa_verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
#     """Verifies a signature using an RSA public key

#     Args:
#         data (bytes): Data to verify
#         signature (bytes): The signature to verify
#         public_key (RSAPublicKey): The public key to use for verification

#     Returns:
#         bool: True if signature is valid, False if not
#     """
#     try:
#         public_key.verify(
#             signature=signature,
#             data=data,
#             padding=padding.PKCS1v15(),
#             algorithm=hashes.SHA512()
#         )
#         return True
#     except InvalidSignature:
#         raise InvalidSignature('Invalid signature: The signature does not match the certificate')

@dataclass 
class DSAPublicKey(PublicKeyClass):
    comment: bytes
    raw_bytes: bytes
    key_type: bytes
    p: int
    q: int
    g: int
    y: int
    
    @classmethod
    def from_bytes(cls, key_data: bytes):
        split = key_data.split(b' ')
        comment = split[2] if split[2] is not None else ''
        raw_bytes = b64decode(split[1])
        
        key_type, data = utils.decode_string(raw_bytes)
        p, data = utils.decode_mpint(data)
        q, data = utils.decode_mpint(data)
        g, data = utils.decode_mpint(data)
        y, _    = utils.decode_mpint(data)
        
        return cls(comment, raw_bytes, key_type, p, q, g, y)
    
    @classmethod
    def from_numbers(cls, p: int, q: int, g: int, y: int, comment: utils.StrOrBytes = '', key_type: str = 'ssh-dss'):
        raw_bytes = utils.encode_string(key_type) + \
                    utils.encode_mpint(p) + \
                    utils.encode_mpint(q) + \
                    utils.encode_mpint(g) + \
                    utils.encode_mpint(y)
                    
        return cls(comment, raw_bytes, key_type, p, q, g, y)

@dataclass
class ECDSAPublicKey(PublicKeyClass):
    comment: bytes
    raw_bytes: bytes
    key_type: bytes
    key_curve: bytes
    key_data: bytes
    
    @classmethod
    def from_bytes(cls, key_data: bytes) -> 'ECDSAPublicKey':
        split = key_data.split(b' ')
        comment = split[2] if split[2] is not None else ''
        raw_bytes = b64decode(split[1])
        
        key_type, data = utils.decode_string(raw_bytes)
        key_curve, data = utils.decode_string(data)
        key_data, _ = utils.decode_string(data)

        return cls(comment, raw_bytes, key_type, key_curve, key_data)
    
    @classmethod
    def from_parts(cls, key_data: bytes, key_curve: str, comment: utils.StrOrBytes, key_type: str):
        raw_bytes = utils.encode_string(key_type) + \
                    utils.encode_string(key_curve) + \
                    utils.encode_string(key_data)
                    
        return cls(comment, raw_bytes, key_type, key_curve, key_data)

class ED25519PublicKey(PublicKeyClass):
    comment: bytes
    raw_bytes: bytes
    key_type: bytes
    key_data: bytes
    
    @classmethod
    def from_bytes(cls, key_data: bytes) -> 'ED25519PublicKey':
        split = key_data.split(b' ')
        comment = split[2] if split[2] is not None else ''
        raw_bytes = b64decode(split[1])
        
        key_type, data = utils.decode_string(raw_bytes)
        key_data, _ = utils.decode_string(data)
        
        return cls(comment, raw_bytes, key_type)

class PublicKey(PublicKeyClass):
    @staticmethod
    def determine_type(
        key: utils.StrOrBytes, 
        encoding: str = 'utf-8'
    ):
        if key is None:
            raise ValueError('The key data cannot be blank')
        
        if isinstance(key, str):
            key = key.encode(encoding)
        
        if b'-cert-v01' in key:
            raise ValueError(
                "This is an SSH Certificate, not a public key. " +
                "Load it via the sshkey_tools.certificate functions instead"
                )

        if b'rsa' in key:
            return RSAPublicKey
        if b'dss' in key:
            return DSAPublicKey
        if b'ecdsa' in key:
            return ECDSAPublicKey
        if b'ed25519' in key:
            return ED25519PublicKey
        
        raise ValueError('Invalid key type or data formatting')
    
    @classmethod
    def from_string(
        cls, 
        key_data: utils.StrOrBytes, 
        encoding: str = 'utf-8'
    ):
        if isinstance(key_data, str):
            key_data = key_data.encode(encoding)
        
        return cls.determine_type(key_data).from_bytes(key_data)
    
    @classmethod
    def from_file(
        cls, 
        file_path: str
    ):
        with open(file_path, 'rb') as f:
            return cls.from_string(f.read())

class PrivateKeyClass:
    def __init__(self, 
        key_object: PrivkeyClasses,
        password: utils.StrOrBytes = None,
    ):
        self.key_object = key_object

class RSAPrivateKey(PrivateKeyClass):
    def __init__(
            self, 
            key_object: _RSAPrivateKey,
            algorithm: c_hashes.HashAlgorithm = c_hashes.SHA512
        ):
        super().__init__(key_object)
        self.algorithm = algorithm


    def sign_data(self, data: bytes) -> tuple[bytes]:
        return self.key_object.sign(
            data=data,
            padding=c_padding.PKCS1v15,
            algorithm=self.algorithm
        )

class DSAPrivateKey(PrivateKeyClass):
    pass

class ECDSAPrivateKey(PrivateKeyClass):
    # def __ini
    pass

class ED25519PrivateKey(PrivateKeyClass):
    pass

PrivateKeyTypes = {
    _RSAPrivateKey: RSAPrivateKey,
    _DSAPrivateKey: DSAPrivateKey,
    _EllipticCurvePrivateKey: ECDSAPrivateKey,
    _Ed25519PrivateKey: ED25519PrivateKey
}

class PrivateKey(PrivateKeyClass):
    @classmethod
    def from_string(
        cls,
        key_data: utils.StrOrBytes,
        password: utils.StrOrBytes = None,
        encoding: str = 'utf-8'
    ):
        if isinstance(key_data, str):
            key_data = key_data.encode(encoding)
            
        obj = c_serialization.load_ssh_private_key(
            data=key_data,
            password=password
        )
    
        return PrivateKeyTypes[type(obj)](obj)
    
    @classmethod
    def from_file(
        cls,
        file_path: str,
        password: utils.StrOrBytes = None,
        encoding: str = 'utf-8'
    ):
        with open(file_path, 'rb') as f:
            return cls.from_string(f.read(), password, encoding)