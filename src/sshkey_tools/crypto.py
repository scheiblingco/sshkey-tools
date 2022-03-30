from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes as crypto_hashes

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey
from cryptography.hazmat.backends.openssl.dsa import _DSAPrivateKey
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey
from cryptography.hazmat.backends.openssl.ed25519 import _Ed25519PrivateKey


from cryptography.hazmat.primitives.serialization import PublicFormat
from base64 import b64encode, b64decode
from enum import Enum
from . import utils
# from . import certificates as cert

class PublicKeyBytes(Enum):
    USER = 'user'
    CA   = 'ca'
    
class PublicKeyClass:
    def __init__(
        self, 
        key_data: bytes, 
        encoding: str = 'utf-8' 
    ):

        self.key_object = crypto_serialization.load_ssh_public_key(
            data=key_data,
            backend=crypto_default_backend()
        )
        
        split = key_data.split(b' ')
        self.raw_bytes = b64decode(split[1])
        self.key_comment = split[2].decode(encoding)
        
    def key_type(self):
        return utils.decode_string(self.raw_bytes)[0]
        
    def key_bytes(self, format: PublicKeyBytes):
        if format == PublicKeyBytes.USER:
            return utils.decode_string(self.raw_bytes)[1]

        elif format == PublicKeyBytes.CA:
            return self.raw_bytes
        
        raise ValueError("Invalid format")

class RSAPublicKey(PublicKeyClass):
    @classmethod
    def from_public_numbers(cls, e: int, n: int):
        return cls(
            key_data=b64encode(
                RSAPublicNumbers(e, n).public_key(default_backend()).public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).decode('utf-8')
        )
    
    
class DSAPublicKey(PublicKeyClass):
    pass
class ECDSAPublicKey(PublicKeyClass):
    def key_curve(self):
        return utils.decode_string(
            utils.decode_string(self.raw_bytes)[1]
        )[0]

class ED25519PublicKey(PublicKeyClass):
    pass

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
        
        return cls.determine_type(key_data)(key_data)
    
    @classmethod
    def from_file(
        cls, 
        file_path: str
    ):
        with open(file_path, 'rb') as f:
            return cls.from_string(f.read())

class PrivateKeyClass:
    def __init__(self, 
        key_object: bytes,
        password: utils.StrOrBytes = None,
    ):
        self.key_object = key_object

class RSAPrivateKey(PrivateKeyClass):
    pass

class DSAPrivateKey(PrivateKeyClass):
    pass

class ECDSAPrivateKey(PrivateKeyClass):
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
            
        obj = crypto_serialization.load_ssh_private_key(
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