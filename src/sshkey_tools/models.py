import os
from dataclasses import dataclass
from .crypto import Algorithm, RSA, DSA, ECDSA, ED25519

@dataclass
class KeyData:
    key_data: str
    
    def from_file(self, path: str) -> None:
        try:
            with open(path, 'r') as f:
                self.key_data = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"File {path} not found")
        except PermissionError:
            raise PermissionError(f"File {path} is not readable")
        
    def from_string(self, private_key: str) -> None:
        self.private_key = private_key
        
    def to_file(self, path: str, overwrite: bool = False) ->  None:
        if self.key_data is None:
            raise ValueError("No private key has been loaded")
        
        if os.path.isfile(path) and not overwrite:
            raise FileExistsError(f"File {path} already exists, use overwrite=True to overwrite")
        
        try:
            with open(path, 'w') as f:
                f.write(self.key_data)
        except PermissionError:
            raise PermissionError(f"File {path} is not writable")
        
    def __str__(self):
        return self.key_data

@dataclass
class PublicKey(KeyData):
    pass


@dataclass
class PrivateKey(KeyData):
    alg: Algorithm
    bits: int
    password: str
    name: str
        
    def get_public_key(self) -> PublicKey:
        if self.key_data is None:
            raise ValueError("No private key has been loaded")
        
        return "CHANGEME: PrivateKey"
    
    def generate(self, bits: int, type: str = 'ecdsa', generate_both: bool = False) -> None:
        pass

    
@dataclass
class CertificateAuthority:
    private_key: PrivateKey
    public_key: PublicKey
    secret: str
        
        
@dataclass
class Certificate(KeyData):
    user_id: str
    principals: list
    serial: int
    validity: str
    ca: CertificateAuthority
    public_key: PublicKey
    certificate: str    
    
    def sign(self):
        pass
    
    def from_string(self):
        pass
    
    def from_file(self):
        pass
    
    def get_info(self):
        pass
    
    def to_string(self):
        pass
    
    def to_file(self):
        pass