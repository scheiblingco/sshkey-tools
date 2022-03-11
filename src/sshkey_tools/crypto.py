from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend

@dataclass
class Algorithm:
    bits: int = 0
    password: str = None
    
    @classmethod
    def load_private_key(self, key_data: bytes, password: str = None):
        try:
            self.key = crypto_serialization.load_pem_private_key(
                key_data,
                password=password.encode() if password is not None else None,
                backend=crypto_default_backend()
            )
        except ValueError:
            self.key = crypto_serialization.load_ssh_private_key(
                key_data,
                password=password.encode() if password is not None else None,
                backend=crypto_default_backend()
            )
            
        print(self.key)
        print(self.key.public_key())
    
    def get_private_key(self):       
        enc = crypto_serialization.NoEncryption()
        if self.password is not None:
            enc = crypto_serialization.BestAvailableEncryption(self.password)
            
        return self.key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        )
    
    def get_public_key(self):
        return self.key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
        )
    

@dataclass
class RSA(Algorithm):
    def gen_private_key(self):
        self.key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=self.bits
        )
        self.key.private_bytes()

@dataclass
class DSA(Algorithm):
    def gen_private_key(self):
        self.key = dsa.generate_private_key(
            key_size=self.bits,
            backend=crypto_default_backend()
        )

@dataclass
class ECDSA(Algorithm):
    def gen_private_key(self):
        if self.bits not in [256, 384, 521]:
            raise ValueError("Invalid bit count for ECDSA")
        
        curve = ec.SECP256R1()
        if self.bits == 384:
            curve = ec.SECP384R1()
        elif self.bits == 521:
            curve = ec.SECP521R1()
        
        self.key = ec.generate_private_key(
            curve=curve,
            backend=crypto_default_backend()
        )
    

@dataclass
class ED25519(Algorithm):
    def gen_private_key(self):
        self.key = ed25519.Ed25519PrivateKey.generate()