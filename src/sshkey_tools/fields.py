from typing import Union, Tuple
from enum import Enum
from struct import pack, unpack
from base64 import b64decode, b64encode
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, 
    encode_dss_signature
)

from .keys import (
    PrivateKey, 
    PublicKey,
    RSAPublicKey,
    RSAPrivateKey,
    DSAPublicKey,
    DSAPrivateKey,
    ECDSAPublicKey,
    ECDSAPrivateKey,
    ED25519PublicKey,
    ED25519PrivateKey,
    ECDSA_CURVES,
    RSA_ALGS
)
from .exceptions import (
    InvalidCertificateFieldException,
    InvalidDataException,
    InvalidKeyException,
    ShortNonceException,
    IntegerOverflowException
)
from .utils import (
    long_to_bytes, 
    bytes_to_long,
    generate_secure_nonce
)

STR_OR_BYTES = Union[str, bytes]
LIST_OR_TUPLE = Union[list, tuple]

ECDSA_CURVE_MAP = {
    'secp256r1': 'nistp256',
    'secp384r1': 'nistp384',
    'secp521r1': 'nistp521'
}

SUBJECT_PUBKEY_MAP = {
    RSAPublicKey: 'RSAPubkeyField',
    DSAPublicKey: 'DSAPubkeyField',
    ECDSAPublicKey: 'ECDSAPubkeyField',
    ED25519PublicKey: 'ED25519PubkeyField'
}

CA_SIGNATURE_MAP = {
    RSAPrivateKey: 'RSASignatureField',
    DSAPrivateKey: 'DSASignatureField',
    ECDSAPrivateKey: 'ECDSASignatureField',
    ED25519PrivateKey: 'ED25519SignatureField'
}

SIGNATURE_TYPE_MAP = {
    b'rsa': 'RSASignatureField',
    b'dss': 'DSASignatureField',
    b'ecdsa': 'ECDSASignatureField',
    b'ed25519': 'ED25519SignatureField'
}


class CERT_TYPE(Enum):
    USER = 1
    HOST = 2


class CertificateField:
    is_set = None
    
    def __init__(self, value, name = None):
        self.name = name
        self.value = value
        self.exception = None
        self.is_set = True        

    def __str__(self):
        return f"{self.name}: {self.value}"
    
    @staticmethod
    def encode(value) -> bytes:
        pass
    
    @staticmethod
    def decode(value: bytes):
        pass
    
    def __bytes__(self) -> bytes:
        return self.encode(self.value)
                
    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['CertificateField', bytes]:
        value, data = cls.decode(data)
        return cls(value), data

class BooleanField(CertificateField):
    @staticmethod
    def encode(value: bool) -> bytes:
        """Encodes a boolean value to a byte string
        Args:
            source_bool (bool): Boolean to encode

        Returns:
            str: Packed byte representing the boolean
        """
        return pack('B', 1 if value else 0)
    
    @staticmethod
    def decode(data: bytes) -> Tuple[bool, bytes]:
        """Decodes a boolean from a bytestring

        Args:
            source_bytes (bytes): The byte string to get the data from
        """
        return bool(unpack('B', data[:1])[0]), data[1:]

class StringField(CertificateField):
    @staticmethod
    def encode(value: STR_OR_BYTES, encoding: str = 'utf-8') -> bytes:
        """Encodes a string or bytestring into a packed byte string

        Args:
            source_string (str, bytes): The string to encode

        Returns:
            bytes: Packed byte string containing the source data
        """
        if isinstance(value, str):
            value = value.encode(encoding)

        if isinstance(value, bytes):
            return pack('>I', len(value)) + value

        raise InvalidDataException(f"Expected unicode or bytes, got {type(value).__name__}.")
        
    @staticmethod
    def decode(data: bytes) -> Tuple[str, bytes]:
        """Unpacks the next string from a packed byte string

        Args:
            data (bytes): The packed byte string to unpack

        Returns:
            (str, data):    The next string from the packed byte 
                            string and remainder of the data
        """
        length = unpack('>I', data[:4])[0] + 4
        return data[4:length], data[length:]
    
class Integer32Field(CertificateField):
    @staticmethod
    def encode(value: int) -> bytes:
        """Encodes a 32-bit integer value to a packed byte string

        Args:
            source_int (int): Integer to be packed

        Returns:
            bytes: Packed byte string containing integer
        """
        if not isinstance(value, int):
            raise InvalidDataException(f"Expected integer, got {type(value).__name__}.")

        return pack('>I', value)
    
    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a 32-bit integer from a block of bytes

        Args:
            data (bytes): Block of bytes containing an integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        return int(unpack('>I', data[:4])[0]), data[4:]
    
class Integer64Field(CertificateField):
    @staticmethod
    def encode(value: int) -> bytes:
        """Encodes a 64-bit integer value to a packed byte string

        Args:
            source_int (int): Integer to be packed

        Returns:
            bytes: Packed byte string containing integer
        """
        if not isinstance(value, int):
            raise InvalidDataException(f"Expected integer, got {type(value).__name__}.")

        return pack('>Q', value)
    
    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a 64-bit integer from a block of bytes

        Args:
            data (bytes): Block of bytes containing an integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        return int(unpack('>Q', data[:8])[0]), data[8:]
    
class TimeField(Integer64Field):
    @staticmethod
    def encode(value: datetime) -> bytes:
        return Integer64Field.encode(int(value.timestamp()))
        
    @staticmethod
    def decode(data: bytes) -> datetime:
        timestamp, data = Integer64Field.decode(data)

        return datetime.fromtimestamp(
            timestamp
        ), data
    
class MpIntegerField(CertificateField):
    @staticmethod
    def encode(value: int) -> bytes:
        """Encodes a multiprecision integer (integer larger than 64bit)
        into a packed byte string

        Args:
            source_int (int): Large integer

        Returns:
            bytes: Packed byte string containing integer
        """
        return StringField.encode(
            long_to_bytes(value)
        )
        
    @staticmethod
    def decode(data: bytes) -> Tuple[int, bytes]:
        """Decodes a multiprecision integer (integer larger than 64bit)

        Args:
            data (bytes): Block of bytes containing a long (mp) integer

        Returns:
            tuple: Tuple with integer and remainder of data
        """
        mpint, data = StringField.decode(data)
        return bytes_to_long(mpint), data
    
class StandardListField(CertificateField):
    @staticmethod
    def encode(value: LIST_OR_TUPLE) -> bytes:
        """Encodes a list or tuple to a byte string

        Args:
            source_list (list): list of strings
            null_separator (bool, optional): Insert blank string string between items. Default None

        Returns:
            bytes: Packed byte string containing the source data
        """
        if sum([ not isinstance(item, STR_OR_BYTES) for item in value]) > 0:
            raise TypeError("Expected list or tuple containing strings or bytes")

        return StringField.encode(
            b''.join(
                [
                    StringField.encode(x) for x in value
                ]
            )
        )
    
    @staticmethod
    def decode(data: bytes) -> Tuple[list, bytes]:
        """Decodes a list of strings from a block of bytes

        Args:
            data (bytes): The block of bytes containing a list of strings
        Returns:
            tuple: _description_
        """
        list_bytes, data = StringField.decode(data)
            
        decoded = []
        while len(list_bytes) > 0:
            elem, list_bytes = StringField.decode(list_bytes)
            decoded.append(elem)
            
        return decoded, data
    
class SeparatedListField(CertificateField):
    @staticmethod
    def encode(value: LIST_OR_TUPLE) -> bytes:
        """Encodes a list or tuple to a byte string separated by a null byte

        Args:
            source_list (list): list of strings

        Returns:
            bytes: Packed byte string containing the source data
        """
        if sum([ not isinstance(item, STR_OR_BYTES) for item in value ]) > 0:
            raise TypeError("Expected list or tuple containing strings or bytes")

        if len(value) < 1:
            return StandardListField.encode(value)

        null_byte = StringField.encode('')

        return StringField.encode(
            null_byte.join(
                StringField.encode(item) for item in value
            ) + null_byte
        )
        
    @staticmethod
    def decode(data: bytes) -> Tuple[list, bytes]:
        """Decodes a list of strings from a block of bytes

        Args:
            data (bytes): The block of bytes containing a list of strings
        Returns:
            tuple: _description_
        """
        list_bytes, data = StringField.decode(data)
            
        decoded = []
        while len(list_bytes) > 0:
            elem, list_bytes = StringField.decode(list_bytes)

            if elem != b'':
                decoded.append(elem)
            
        return decoded, data
   
class PubkeyTypeField(StringField):
    def __init__(self, value: str):
        super().__init__(
            value=value,
            name='pubkey_type',
        )
        
    def validate(self) -> bool:
        if self.value not in (
            'ssh-rsa-cert-v01@openssh.com',
            'rsa-sha2-256-cert-v01@openssh.com',
            'rsa-sha2-512-cert-v01@openssh.com',
            'ssh-dss-cert-v01@openssh.com',
            'ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ecdsa-sha2-nistp384-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521-cert-v01@openssh.com',
            'ssh-ed25519-cert-v01@openssh.com'
        ):
            self.exception = InvalidDataException(f"Invalid pubkey type: {self.value}")
            return False
        
        return True and self.is_set
        
class NonceField(StringField):
    def __init__(self, value: str = None):
        super().__init__(
            value=value if value is not None else generate_secure_nonce(),
            name='nonce'
        )

    def validate(self) -> bool:
        return self.is_set

class PublicKeyField(CertificateField):
    def __init__(self, value: PublicKey):
        super().__init__(
            value=value,
            name='public_key'
        )

    @staticmethod
    def from_object(public_key: PublicKey):
        try:
            return globals()[SUBJECT_PUBKEY_MAP[public_key.__class__]](
                value=public_key
            )
        except KeyError:
            raise InvalidKeyException("The public key is invalid")
        
    @classmethod
    def from_decode(cls, data: bytes):
        key, data = cls.decode(data)
        return cls(key), data

class RSAPubkeyField(PublicKeyField):
    @staticmethod
    def encode(value: RSAPublicKey) -> bytes:
        return (
            MpIntegerField.encode(value.public_numbers.e) +
            MpIntegerField.encode(value.public_numbers.n)
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[RSAPublicKey, bytes]:
        e, data = MpIntegerField.decode(data)
        n, data = MpIntegerField.decode(data)
        
        return RSAPublicKey.from_numbers(
            e=e,
            n=n 
        ), data
        
   
        
    def validate(self) -> bool:
        return self.is_set and isinstance(
            self.value,
            RSAPublicKey
        )

class DSAPubkeyField(PublicKeyField):
    @staticmethod
    def encode(value: DSAPublicKey) -> bytes:
        return (
            MpIntegerField.encode(value.parameters.p) +
            MpIntegerField.encode(value.parameters.q) +
            MpIntegerField.encode(value.parameters.g) +
            MpIntegerField.encode(value.public_numbers.y)
        )
        
    @staticmethod
    def decode(data: bytes) -> Tuple[DSAPublicKey, bytes]:
        p, data = MpIntegerField.decode(data)
        q, data = MpIntegerField.decode(data)
        g, data = MpIntegerField.decode(data)
        y, data = MpIntegerField.decode(data)
        
        return DSAPublicKey.from_numbers(
            p=p, q=q, g=g, y=y
        ), data
       
    def validate(self) -> bool:
        return self.is_set and isinstance(
            self.value,
            DSAPublicKey
        )
 
class ECDSAPubkeyField(PublicKeyField):   
    @staticmethod
    def encode(value: ECDSAPublicKey) -> bytes:
        _, pubkey = StringField.decode(b64decode(value.serialize().split(b' ')[1]))

        return pubkey
    
    @staticmethod
    def decode(data: bytes) -> Tuple[ECDSAPublicKey, bytes]:
        curve, data = StringField.decode(data)
        key, data = StringField.decode(data)

        key_type = b'ecdsa-sha2-' + curve

        return ECDSAPublicKey.from_string(
            key_type + b' ' +
            b64encode(
                StringField.encode(key_type) +
                StringField.encode(curve) +
                StringField.encode(key)
            )
        ), data
        
    def validate(self) -> bool:
        return self.is_set and isinstance(
            self.value,
            ECDSAPublicKey
        )
    
class ED25519PubkeyField(PublicKeyField):
    @staticmethod
    def encode(value: ED25519PublicKey) -> bytes:
        return (
            StringField.encode(value.raw_bytes())
        )
        
    @staticmethod
    def decode(data: bytes) -> Tuple[ED25519PublicKey, bytes]:
        pubkey, data = StringField.decode(data)
        
        return ED25519PublicKey.from_raw_bytes(
            pubkey
        ), data
         
    def validate(self) -> bool:
        return self.is_set and isinstance(
            self.value,
            ED25519PublicKey
        )


class SerialField(Integer64Field):
    def __init__(self, value: int):
        super().__init__(
            value=value,
            name='serial'
        )
        
    def validate(self) -> bool:
        if len(str(self.value)) > (2^63 - 1):
            self.exception = IntegerOverflowException(
                "The serial number is too large to be represented in 64 bits"
            )
            return False
        
        return self.is_set and True

class CertificateTypeField(Integer32Field):
    def __init__(self, value: Union[CERT_TYPE, int]):
        super().__init__(
            value=value.value if isinstance(value, CERT_TYPE) else value,
            name='type'
        )
        
    def validate(self) -> bool:
        if 0 > self.value > 3:
            self.exception = InvalidDataException(
                "The certificate type is invalid (1: User, 2: Host)"
            )
            return False
        
        return self.is_set and True
    
    
    
class KeyIDField(StringField):
    def __init__(self, value: str):
        super().__init__(
            value=value,
            name='key_id'
        )    

    def validate(self) -> bool:
        if self.value in [None, False, '', ' ']:
            self.exception = InvalidDataException(
                "You need to provide a Key ID"
            )
            return False
        
        return True
    
class PrincipalsField(StandardListField):
    def __init__(self, value: LIST_OR_TUPLE):
        super().__init__(
            value=list(value),
            name='principals'
        )
        
    def validate(self) -> bool:
        if self.value in [None, False, [], ()]:
            self.exception = InvalidDataException(
                "You need to provide at least one principal"
            )
            return False
        
        return True

class ValidityStartField(TimeField):
    def __init__(self, value: datetime):
        super().__init__(
            value=value,
            name='valid_after'
        )
        
    def validate(self) -> bool:
        if not isinstance(self.value, datetime):
            self.exception = InvalidDataException(
                "The validity start date is not a datetime object"
            )
            return False
        
        return True
    
class ValidityEndField(TimeField):
    def __init__(self, value: datetime):
        super().__init__(
            value=value,
            name='valid_before'
        )
        
    def validate(self) -> bool:
        if not isinstance(self.value, datetime):
            self.exception = InvalidDataException(
                "The validity end date is not a datetime object"
            )
            return False
        
        return True

class CriticalOptionsField(SeparatedListField):
    def __init__(self, value: LIST_OR_TUPLE):
        super().__init__(
            value=value,
            name='critical_options'
        )
        
    def validate(self) -> bool:
        valid_opts = (
            'force-command',
            'source-address',
            'verify-required'
        )

        for item in self.value:
            present = 0
            for opt in valid_opts:
                if opt in item:
                    present = 1
            if present == 0:
                self.exception = InvalidDataException(
                    f"The critical option '{item}' is invalid"
                )
                return False
        
        return True

class ExtensionsField(SeparatedListField):
    def __init__(self, value: LIST_OR_TUPLE):
        super().__init__(
            value=value,
            name='extensions'
        )
        
    def validate(self) -> bool:
        valid_opts = (
            'no-touch-required',
            'permit-X11-forwarding',
            'permit-agent-forwarding',
            'permit-port-forwarding',
            'permit-pty',
            'permit-user-rc'
        )
        
        for item in self.value:
            if item not in valid_opts:
                self.exception = InvalidDataException(
                    f"The extension '{item}' is invalid"
                )
                return False
            
        return True

class ReservedField(StringField):
    def __init__(self, value: str = ''):
        super().__init__(
            value=value,
            name='reserved'
        )
        
    def validate(self) -> bool:
        if self.value == '':
            return True
        
        self.exception = InvalidDataException(
            f"The reserved field needs to be empty"
        )
        return False    
    
class CAPublicKeyField(StringField):
    def __init__(self, value: STR_OR_BYTES, decoded: bool = False):
        if not decoded:
            value = b64decode(value)

        super().__init__(
            value=value,
            name='ca_public_key'
        )
        
    def validate(self) -> bool:
        if self.value in [None, False, '', ' ']:
            self.exception = InvalidDataException(
                "You need to provide a CA public key"
            )
            return False
        
        return True

    @classmethod
    def from_object(cls, public_key: PublicKey) -> 'CAPublicKeyField':
        return cls(
            value=public_key.serialize().split(b' ')[1]
        )
        
    @classmethod
    def from_decode(cls, data: bytes):
        key, data = cls.decode(data)
        return cls(key, True), data


class SignatureField(CertificateField):
    def __init__(
        self, 
        private_key: PrivateKey = None,
        signature: bytes = None
    ):
        self.private_key = private_key
        self.is_signed = False
        self.value = signature
        
    @staticmethod
    def from_object(private_key: PrivateKey):
        try:
            return globals()[CA_SIGNATURE_MAP[private_key.__class__]](
                private_key=private_key
            )
        except KeyError:
            raise InvalidKeyException('The private key provided is invalid')

    @staticmethod
    def from_decode(cert_bytes: bytes) -> 'SignatureField':
        signature = StringField.decode(cert_bytes)[0]
        signature_type = StringField.decode(signature)[0]
        
        for sig in SIGNATURE_TYPE_MAP.keys():
            if sig in signature_type:
                return globals()[
                    SIGNATURE_TYPE_MAP[sig]
                ].from_decode(cert_bytes)
        
        raise InvalidDataException(
            "No matching signature type found"
        )

    def can_sign(self):
        return False if self.private_key is None else True

    def sign(self, data: bytes) -> None:
        pass
    
    def __bytes__(self) -> None:
        return self.encode(
            self.value
        )
    
class RSASignatureField(SignatureField):
    def __init__(
        self, 
        private_key: RSAPrivateKey = None, 
        hash_alg: RSA_ALGS = RSA_ALGS.SHA512,
        signature: bytes = None
    ):
        super().__init__(private_key, signature)
        self.hash_alg = hash_alg

    @staticmethod
    def encode(signature: bytes, hash_alg: RSA_ALGS = RSA_ALGS.SHA256) -> bytes:
        return StringField.encode(
            StringField.encode(hash_alg.value[0]) + 
            StringField.encode(signature)
        )

    @staticmethod
    def decode(data: bytes) -> Tuple[
        Tuple[
            bytes, 
            bytes
        ], 
        bytes
    ]:
        signature, data = StringField.decode(data)

        sig_type, signature = StringField.decode(signature)
        signature, _ = StringField.decode(signature)

        return (sig_type, signature), data
    
    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['RSASignatureField', bytes]:
        signature, data = cls.decode(data)
   
        return cls(
            private_key=None,
            hash_alg=[alg for alg in RSA_ALGS if alg.value[0] == signature[0].decode('utf-8')][0],
            signature=signature[1]
        ), data

    def sign(
        self, 
        data: bytes, 
        hash_alg: RSA_ALGS = RSA_ALGS.SHA256
    ) -> None:       
        self.value = self.private_key.sign(
            data,
            hash_alg
        )
        
        self.hash_alg = hash_alg
        self.is_signed = True

    def __bytes__(self):
        return self.encode(
            self.value,
            self.hash_alg
        )


class DSASignatureField(SignatureField):
    def __init__(
        self, 
        private_key: DSAPrivateKey = None,
        signature: bytes = None
    ) -> None:
        super().__init__(private_key, signature)

    @staticmethod
    def encode(signature: bytes):
        r, s = decode_dss_signature(signature)

        return StringField.encode(
            StringField.encode('ssh-dss') +
            StringField.encode(
                long_to_bytes(r, 20) +
                long_to_bytes(s, 20)
            )
        )

    @staticmethod
    def decode(data: bytes) -> bytes:
        signature, data = StringField.decode(data)

        signature = StringField.decode(
            StringField.decode(signature)[1]
        )[0]
        r = bytes_to_long(signature[:20])
        s = bytes_to_long(signature[20:])

        signature = encode_dss_signature(r, s)

        return signature, data
    
    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['DSASignatureField', bytes]:
        signature, data = cls.decode(data)
        
        return cls(
            private_key=None,
            signature=signature
        ), data

    def sign(self, data: bytes) -> None:
        self.value = self.private_key.sign(
            data
        )
        self.is_signed = True
    
class ECDSASignatureField(SignatureField):
    def __init__(
        self, 
        private_key: ECDSAPrivateKey = None,
        signature: bytes = None,
        curve_name: str = None
    ) -> None:
        super().__init__(private_key, signature)
        
        if curve_name is None:
            curve_size = self.private_key.public_key.key.curve.key_size
            curve_name = f'ecdsa-sha2-nistp{curve_size}'
        
        self.curve = curve_name
        
    @staticmethod
    def encode(signature: bytes, private_key: ECDSAPrivateKey):
        r, s = decode_dss_signature(signature)
        curve_size = private_key.public_key.key.curve.key_size
        return StringField.encode(
            StringField.encode(
                f'ecdsa-sha2-nistp{curve_size}'
            ) +
            StringField.encode(
                MpIntegerField.encode(r) +
                MpIntegerField.encode(s)
            )
        )

    @staticmethod
    def decode(data: bytes) -> bytes:
        signature, data = StringField.decode(data)

        sig_type, signature = StringField.decode(signature)
        signature, _ = StringField.decode(signature)

        r, signature = MpIntegerField.decode(signature)
        s, _ = MpIntegerField.decode(signature)

        signature = encode_dss_signature(r, s)

        return (sig_type, signature), data
    
    @classmethod
    def from_decode(cls, data: bytes) -> Tuple['ECDSASignatureField', bytes]:
        signature, data = cls.decode(data)
        
        return cls(
            private_key=None,
            signature = signature[1],
            curve_name = signature[0]
        ), data
        
    def sign(self, data: bytes) -> None:
        self.value = self.private_key.sign(
            data
        )
        self.is_signed = True

    def __bytes__(self):
        return self.encode(
            self.value,
            self.private_key
        )

class ED25519SignatureField(SignatureField):
    def __init__(
        self, 
        private_key: ED25519PrivateKey = None, 
        signature: bytes = None
    ) -> None:
        super().__init__(private_key, signature)

    @staticmethod
    def encode(signature: bytes) -> None:
        return StringField.encode(
            StringField.encode('ssh-ed25519') +
            StringField.encode(signature)
        )

    @staticmethod
    def decode(data: bytes) -> bytes:
        signature, data = StringField.decode(data)

        signature = StringField.decode(
            StringField.decode(signature)[1]
        )[0]

        return signature, data
    
    @classmethod
    def from_decode(cls, data: bytes) -> bytes:
        signature, data = StringField.decode(data)
        
        return cls(
            private_key=None,
            signature=signature
        ), data

    def sign(self, data: bytes) -> None:
        self.value = self.private_key.sign(
            data
        )
        self.is_signed = True