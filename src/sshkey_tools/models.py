import os
from dataclasses import dataclass
from .crypto import Algorithm, RSA, DSA, ECDSA, ED25519
from .exceptions import FileAccessException, PasswordNeededException

@dataclass
class KeyData:
    key_data: str = None
    password: str = None
    
    @classmethod
    def from_file(cls, path: str, password: str = None) -> None:
        try:
            with open(path, 'rb') as f:
                return cls(key_data=f.read(), password=password)
        except (FileNotFoundError, PermissionError) as e:
            raise FileAccessException(e)   
        
    @classmethod
    def from_string(cls, key_data: str, password: str = None) -> None:
        return cls(key_data=key_data, password=password)
        
    def to_file(self, path: str, overwrite: bool = False) ->  None:
        if self.key_data is None:
            raise ValueError("No private key has been loaded")
        
        if os.path.isfile(path) and not overwrite:
            raise FileExistsError(f"File {path} already exists, use overwrite=True to overwrite")
        
        mode = 'wb' if isinstance(self.key_data, bytes) else 'w'
        try:
            with open(path, mode) as f:
                f.write(self.key_data)
        except PermissionError:
            raise PermissionError(f"File {path} is not writable")
        
    def __str__(self):
        return self.key_data.decode('utf-8')

@dataclass
class PublicKey(KeyData):
    pass

@dataclass
class PrivateKey(KeyData):
    alg: Algorithm = Algorithm
    bits: int = 0
    password: str = None
    name: str = None
    
    def __post_init__(self):
        if self.key_data is not None:
            self.alg.load_private_key(self.key_data, self.password)
        
    @classmethod
    def generate(cls, algorithm: Algorithm = None, bits: int = None) -> None:
        init_class = cls(alg=algorithm(bits=bits), bits=bits)
        init_class.alg.gen_private_key()
        init_class.key_data = init_class.alg.get_private_key()
        
        return init_class
        
    def get_public_key(self) -> PublicKey:
        if self.key_data is None:
            raise ValueError("No private key has been loaded")
        
        return PublicKey(self.alg.get_public_key())
    
@dataclass
class CertificateAuthority:
    private_key: PrivateKey
    public_key: PublicKey
    secret: str      
        
@dataclass
class Certificate(KeyData):
    user_id: str = None
    principals: list = None
    serial: int = None
    validity: str = None
    ca: CertificateAuthority = None
    public_key: PublicKey = None
    certificate: str =  None
    
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