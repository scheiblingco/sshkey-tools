from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes as crypto_hashes

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend

from cryptography.hazmat.primitives.serialization import PublicFormat
from base64 import b64encode, b64decode
from enum import Enum
from . import utils
from . import certificates as cert

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
        self.cipher = split[0].decode(encoding)
        self.key_bytes = b64decode(split[1])
        self.key_comment = split[2].decode(encoding)

class RSAPublicKey(PublicKeyClass):
    def __init__(
        self,
        key_data: bytes,
        encoding: str = 'utf-8'
    ):
        super().__init__(key_data, encoding)
        self.public_numbers = self.key_object.public_numbers()

class DSAPublicKey(PublicKeyClass):
    def __init__(
        self,
        key_data: bytes,
        encoding: str = 'utf-8'
    ):
        super().__init__(key_data, encoding)
        self.public_parameters = self.key_object.public_parameters()
        self.public_numbers = self.key_object.public_numbers()

class ECDSAPublicKey(PublicKeyClass):
    def __init__(
        self,
        key_data: bytes,
        encoding: str = 'utf-8'
    ):
        super().__init__(key_data, encoding)
        self.cipher, self.key_bytes = utils.decode_string(self.key_data)
        self.curve, self.key_bytes = utils.decode_string(self.key_data)
        self.key_bytes = utils.decode_string(self.key_data)[0]

class ED25519PublicKey(PublicKeyClass):
    def __init__(
        self,
        key_data: bytes,
        encoding: str = 'utf-8'
    ):
        super().__init__(key_data, encoding)
        self.cipher, self.key_bytes = utils.decode_string(self.key_bytes)
        self.key_bytes = utils.decode_string(self.key_bytes)[0]

class PublicKeyTypes(Enum):
    RSAPublicKey = 'ssh-rsa'
    DSAPublicKey = 'ssh-dss'
    ECDSAPublicKey = 'ecdsa-sha2'
    ED25519PublicKey = 'ssh-ed25519'

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

class PrivateKey(PrivateKeyClass):
    pass
    

# class PublicKey:
#     def __init__(self, key_type )
#         pass


# @dataclass
# class Algorithm:
#     bits: int = 0
#     password: str = None

#     @classmethod
#     def load_private_key(self, key_data: bytes, password: str = None):
#         try:
#             self.key = crypto_serialization.load_pem_private_key(
#                 key_data,
#                 password=password.encode() if password is not None else None,
#                 backend=crypto_default_backend()
#             )
#         except ValueError:
#             self.key = crypto_serialization.load_ssh_private_key(
#                 key_data,
#                 password=password.encode() if password is not None else None,
#                 backend=crypto_default_backend()
#             )

#         print(self.key)
#         print(self.key.public_key())

#     def get_private_key(self):
#         enc = crypto_serialization.NoEncryption()
#         if self.password is not None:
#             enc = crypto_serialization.BestAvailableEncryption(self.password)

#         return self.key.private_bytes(
#             encoding=crypto_serialization.Encoding.PEM,
#             format=crypto_serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=enc
#         )

#     def get_public_key(self):
#         return self.key.public_key().public_bytes(
#             crypto_serialization.Encoding.OpenSSH,
#             crypto_serialization.PublicFormat.OpenSSH
#         )


# @dataclass
# class RSA(Algorithm):
#     def gen_private_key(self):
#         self.key = rsa.generate_private_key(
#             backend=crypto_default_backend(),
#             public_exponent=65537,
#             key_size=self.bits
#         )
#         self.key.private_bytes()

# @dataclass
# class DSA(Algorithm):
#     def gen_private_key(self):
#         self.key = dsa.generate_private_key(
#             key_size=self.bits,
#             backend=crypto_default_backend()
#         )

# @dataclass
# class ECDSA(Algorithm):
#     def gen_private_key(self):
#         if self.bits not in [256, 384, 521]:
#             raise ValueError("Invalid bit count for ECDSA")

#         curve = ec.SECP256R1()
#         if self.bits == 384:
#             curve = ec.SECP384R1()
#         elif self.bits == 521:
#             curve = ec.SECP521R1()

#         self.key = ec.generate_private_key(
#             curve=curve,
#             backend=crypto_default_backend()
#         )


# @dataclass
# class ED25519(Algorithm):
#     def gen_private_key(self):
#         self.key = ed25519.Ed25519PrivateKey.generate()