# from dataclasses import dataclass
# from re import I
# from socket import ntohl
from time import time
from enum import Enum
from base64 import b64decode
from . import utils

class CertificateType(Enum):
    USER = 1
    HOST = 2

class CertificateField:
    def __init__(self, value: str):
        self.value = value

class StringField(CertificateField):   
    def to_bytes(self) -> bytes:
        return utils.encode_string(self.value)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'StringField':
        decode = utils.decode_string(data)
        return cls(value=decode[0]), decode[1]
    
class IntegerField(CertificateField):
    def to_bytes(self) -> bytes:
        return utils.encode_int(self.value)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'IntegerField':
        decode = utils.decode_int(data)
        return cls(value=decode[0]), decode[1]

class Integer64Field(CertificateField):
    def to_bytes(self) -> bytes:
        return utils.encode_int64(self.value)
    
    def from_bytes(cls, data: bytes) -> 'Integer64Field':
        decode = utils.decode_int64(data)
        return cls(value=decode[0]), decode[1]
    
class MultiprecisionIntegerField(CertificateField):
    def to_bytes(self) -> bytes:
        return utils.encode_mpint(self.value)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'MultiprecisionIntegerField':
        decode = utils.decode_mpint(data)
        return cls(value=decode[0]), decode[1]
    
class BooleanField(CertificateField):
    def to_bytes(self) -> bytes:
        return utils.encode_boolean(self.value)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'BooleanField':
        decode = utils.decode_boolean(data)
        return cls(value=decode[0]), decode[1]
    
class ListField(CertificateField):
    def __init__(self, value: utils.StrListOrTuple, null_separator: bool = False):
        self.null_separator = null_separator
        super().__init__(value)
    
    def to_bytes(self) -> bytes:
        return utils.encode_list(self.value, self.null_separator)
    
    @classmethod
    def from_bytes(cls, data: bytes, null_separator: bool = False) -> 'ListField':
        decode = utils.decode_list(data, null_separator)
        return cls(value=decode[0], null_separator=null_separator), decode[1]
    
class RSASignatureField(CertificateField):
    def __init__(self, value: bytes, cert_type: utils.StrOrBytes = 'rsa-sha2-512'):
        self.cert_type = cert_type
        super().__init__(value)
        
    def to_bytes(self) -> bytes:
        return utils.encode_rsa_signature(self.value, self.cert_type)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'RSASignatureField':
        decode = utils.decode_rsa_signature(data)
        return cls(value=decode[0], cert_type=decode[1]), decode[2]
    
class DSSSignatureField(CertificateField):
    def __init__(self, r: bytes, s: bytes, cert_type: utils.StrOrBytes):
        self.cert_type = cert_type
        self.r = r
        self.s = s
        
    def to_bytes(self) -> bytes:
        return utils.encode_dss_signature(self.r, self.s, self.cert_type)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DSSSignatureField':
        decode = utils.decode_dss_signature(data)
        return cls(decode[0], decode[1], decode[2]), decode[3]
    
class ECDSASignatureField(CertificateField):
    def __init__(self, r: bytes, s: bytes, curve: utils.StrOrBytes):
        self.curve = curve
        self.r = r
        self.s = s
        
    def to_bytes(self) -> bytes:
        return utils.encode_ecdsa_signature(self.r, self.s, self.curve)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ECDSASignatureField':
        decode = utils.decode_ecdsa_signature(data)
        return cls(decode[0], decode[1], decode[2]), decode[3]

class ED25519SignatureField(CertificateField):
    def __init__(self, value: bytes, cert_type: utils.StrOrBytes):
        self.cert_type = cert_type
        super().__init__(value)
        
    def to_bytes(self) -> bytes:
        return utils.encode_ed25519_signature(self.value, self.cert_type)
    
    @classmethod
    def from_bytes(self, data: bytes) -> 'ED25519SignatureField':
        decode = utils.decode_ed25519_signature(data)
        return self(decode[0], decode[1]), decode[2]
    
class RSAUserPubkeyField(CertificateField):
    def __init__(self, certificate_data: utils.StrOrBytes = None, public_numbers: tuple = None):
        if certificate_data:
            self.certificate_data = certificate_data
            self.pubkey = utils.public_key_to_object(certificate_data)
            self.e = self.pubkey['key'].public_numbers().e
            self.n = self.pubkey['key'].public_numbers().n
            
        if public_numbers:
            self.e, self.n = public_numbers
        
    def to_bytes(self) -> bytes:
        self.e_bytes = utils.encode_mpint(self.e)
        self.n_bytes = utils.encode_mpint(self.n)
                    
        return self.e_bytes + self.n_bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'RSAUserPubkeyField':
        e_bytes, data = utils.decode_mpint(data)
        n_bytes, data = utils.decode_mpint(data)
        
        return cls(None, (e_bytes, n_bytes)), data

class DSSUserPubkeyField(CertificateField):
    def __init__(self, certificate_data: utils.StrOrBytes = None, public_numbers: tuple = None):
        if certificate_data:
            self.certificate_data = certificate_data
            self.pubkey = utils.public_key_to_object(certificate_data)
            self.p = self.pubkey.public_numbers().p
            self.q = self.pubkey.public_numbers().q
            self.g = self.pubkey.public_numbers().g
            self.y = self.pubkey.parameters().parameter_numbers().y
            
        if public_numbers:
            self.p, self.q, self.g, self.y = public_numbers
            
    def to_bytes(self) -> bytes:
        self.p_bytes = utils.encode_mpint(self.p)
        self.q_bytes = utils.encode_mpint(self.q)
        self.g_bytes = utils.encode_mpint(self.g)
        self.y_bytes = utils.encode_mpint(self.y)
        
        return self.p_bytes + self.q_bytes + self.g_bytes + self.y_bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DSSUserPubkeyField':
        p, data = utils.decode_mpint(data)
        q, data = utils.decode_mpint(data)
        g, data = utils.decode_mpint(data)
        y, data = utils.decode_mpint(data)
        
        return cls(None, (p, q, g, y)), data
    
class ECDSAUserPubkeyField(CertificateField):
    def __init__(self, certificate_data: utils.StrOrBytes = None, decoded_data: bytes = None):
        if certificate_data:
            self.certificate_data = certificate_data
            split = b' ' if isinstance(certificate_data, bytes) else b' '
            cert = b64decode(certificate_data.split(split))
            
            self.pubkey = utils.public_key_to_object(certificate_data)
            self.type, cert = utils.decode_string(cert)
            self.curve, cert = utils.decode_string(cert)
            self.keydata = utils.decode_string(cert)[0]
            
        if decoded_data:
            self.curve = decoded_data[0]
            self.keydata = decoded_data[1]
            
    def to_bytes(self) -> bytes:
        self.encoded_curve = utils.encode_string(self.curve)
        self.encoded_cert = utils.encode_string(self.keydata)
        
        return self.encoded_curve + self.encoded_cert
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ECDSAUserPubkeyField':
        curve, data = utils.decode_string(data)
        keydata, data = utils.decode_string(data)
        
        return cls(None, (curve, keydata)), data

class ED25519UserPubkeyField(CertificateField):
    def __init__(self, certificate_data: utils.StrOrBytes, decoded_data: tuple = None):
        if certificate_data:
            self.certificate_data = certificate_data
            self.pubkey = utils.public_key_to_object(certificate_data)
            
            split = b' ' if isinstance(certificate_data, bytes) else b' '
            cert = b64decode(certificate_data.split(split))
            self.type, cert = utils.decode_string(cert)
            self.keydata = utils.decode_string(cert)[0]
        
        else:
            self.type = decoded_data[0]
            self.keydata = decoded_data[1]
            
    def to_bytes(self) -> bytes:
        self.encoded_type = utils.encode_string(self.type)
        self.encoded_cert = utils.encode_string(self.keydata)
        return self.encoded_type + self.encoded_cert
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ED25519UserPubkeyField':
        type, data = utils.decode_string(data)
        keydata, data = utils.decode_string(data)
        
        return cls(None, (type, keydata)), data
    
class NonceField(CertificateField):
    def __init__(self, length: int = 64, nonce: utils.StrOrBytes = None):
        self.length = 64
        self.nonce = str(utils.generate_secure_nonce(self.length)) if not nonce else nonce
        
    def to_bytes(self) -> bytes:
        return utils.encode_string(self.nonce)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'NonceField':
        nonce, data = utils.decode_string(data)
        length = len(nonce)
        
        return cls(length, nonce), data
    
class TimeField(Integer64Field):
    def __init__(self, offset: int = 0, value: int = None):
        self.value = int(time()) + offset
        
    def __bytes__(self) -> bytes:
        return self.to_bytes()
    
class CertificateTypeField(IntegerField):
    def __init__(self, type: CertificateType):
        self.value = type.value