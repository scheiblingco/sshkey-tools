from dataclasses import dataclass
from enum import Enum
from . import utils
from . import fields
from . import crypto

@dataclass
class CertificateAttributes:
    format: fields.StringField = None
    nonce: fields.NonceField = None
    pubkey: fields.PubkeyField = None
    serial: fields.Integer64Field = None
    cert_type: fields.IntegerField = None
    key_id: fields.StringField = None
    principals: fields.PrincipalListField = None
    valid_after: fields.TimeField = None
    valid_before: fields.TimeField = None
    critical_options: fields.CriticalOptionsListField = None
    extensions: fields.ExtensionsListField = None
    reserved: fields.StringField = None
    ca_pubkey: fields.PubkeyField = None
    ca_signature: fields.SignatureField = None

class RSAHashAlgorithms(Enum):
    SHA1 = 'ssh-rsa'
    SHA256 = 'rsa-sha2-256'
    SHA512 = 'rsa-sha2-512'
    
class CertificateTypes(Enum):
    USER = 1
    HOST = 2

class Certificate:
    def __init__(
        self, 
        public_key: crypto.PublicKeyClass,
        nonce_bytes: int = 64
    ):
        self.public_key = public_key
        self.attributes = CertificateAttributes
        self.attributes.user_pubkey.from_string(
            public_key.key_bytes(
                crypto.PublicKeyBytes.USER
            )
        ) 
        self.attributes.nonce.set(nonce_bytes)
            
class RSACertificate(Certificate):
    def __init__(
        self,
        public_key: crypto.PublicKeyClass,
        cert_type: CertificateTypes,
        nonce_bytes: int = 64,
        hash_alg: RSAHashAlgorithms = RSAHashAlgorithms.SHA512
    ):
        super().__init__(public_key, nonce_bytes)
        self.hash_alg = hash_alg
        self.attributes.format.set(self.hash_alg.value + '-cert-v01@openssh.com')