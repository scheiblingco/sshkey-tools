from typing import Union, Tuple
from struct import pack, unpack
from base64 import b64decode, b64encode
from datetime import datetime

from .keys import (
    PrivateKey, 
    PublicKey,
    RSAPublicKey,
    DSAPublicKey,
    ECDSAPublicKey,
    ED25519PublicKey
)
from .exceptions import (
    InvalidDataException,
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

class CertificateField:
    def __init__(self, value, name = None):
        self.name = name
        self.value = value
        self.exception = None

    def __str__(self):
        return f"{self.name}: {self.value}"
    
    @staticmethod
    def encode(value):
        pass
    
    @staticmethod
    def decode(value):
        pass
    
    def __bytes__(self):
        return self.encode(self.value)

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
        super().encode(int(value.timestamp()))
        
    @staticmethod
    def decode(value: datetime) -> bytes:
        timestamp, data = super().decode(data)

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
        mpint, remainder = StringField.decode(data)
        return bytes_to_long(mpint), remainder
    
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
            name='pubkey_type'
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
        
        return True
        
class NonceField(StringField):
    def __init__(self, value: str = None):
        if value is None:
            value = generate_secure_nonce()
        
        super().__init__(
            value=value,
            name='nonce'
        )
        
        
    def validate(self) -> bool:
        if len(self.value) < 32:
            self.exception = ShortNonceException(
                "The nonce is too short to be secure, use at least 32 bits"
            )
            return False
        
        return True
    
class PublicKeyField(CertificateField):
    def __init__(self, value: PublicKey):
        super().__init__(
            value=value,
            name='public_key'
        )
    
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
 
class ECDSAPubkeyField(PublicKeyField):   
    @staticmethod
    def encode(value: ECDSAPublicKey) -> bytes:
        cert_bytes = b64decode(value.to_bytes().split(b' ')[1])
        from cryptography.hazmat.primitives import serialization

        return StringField.decode(cert_bytes)[1]
    
    @staticmethod
    def decode(data: bytes) -> Tuple[ECDSAPublicKey, bytes]:
        curve, _ = StringField.decode(data)
                
        key_type = b'ecdsa-sha2-' + curve
        
        return ECDSAPublicKey.from_string(
            key_type + b' ' + b64encode(
                StringField.encode(key_type) + data
            )
        )
    
class ED25519PubkeyField(PublicKeyField):
    @staticmethod
    def encode(value: ED25519PublicKey) -> bytes:
        return (
            StringField.encode('ssh-ed25519') +
            StringField.encode(value.raw_bytes())
        )
        
    @staticmethod
    def decode(data: bytes) -> Tuple[ED25519PublicKey, bytes]:
        _, data = StringField.decode(data)
        pubkey, data = StringField.decode(data)
        
        return ED25519PublicKey.from_raw_bytes(
            pubkey
        ), data


class SerialField(Integer64Field):
    def __init__(self, value: int):
        super().__init__(
            value=value,
            name='serial'
        )
        
    def validate(self) -> bool:
        if self.value > (2^63 - 1):
            self.exception = IntegerOverflowException(
                "The serial number is too large to be represented in 64 bits"
            )
            return False
        
        return True

class CertificateTypeField(Integer32Field):
    def __init__(self, value: int):
        super().__init__(
            value=value,
            name='cert_type'
        )
        
    def validate(self) -> bool:
        if self.value > 2:
            self.exception = InvalidDataException(
                "The certificate type is invalid (1: User, 2: Host)"
            )
            return False
        
        return True
    
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
            value=value,
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
            if present = 0:
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
    def __init__(self):
        super().__init__(
            value='',
            name='reserved'
        )
        
    def validate(self) -> bool:
        return True
    
class SignatureField(CertificateField):
    def __init__(self, value: bytes):
        super().__init__(
            value=value,
            name='signature'
        )
    
class RSASignatureField(SignatureField):
    @staticmethod
    def encode(self, signature: RSASignature):
        
    
    pass
#     def encode_rsa_signature(signature: bytes, cert_type: StrOrBytes = 'ssh-rsa') -> bytes:
#     """Encodes an RSA signature to the OpenSSH Certificate format

#     Args:
#         signature (bytes): The signature data
#         cert_type (str, bytes): The type, default ssh-rsa

#     Returns:
#         _type_: Byte string with the encoded certificate
#     """
#     return encode_string( encode_string(cert_type) + encode_string(signature) )

# def decode_rsa_signature(data: bytes) -> tuple:
#     """Decodes an RSA signature from the OpenSSH Certificate format

#     Args:
#         data (bytes): The block of bytes containing the signature

#     Returns:
#         tuple: Tuple containing the signature and remainder of the data
#     """
#     layer_one, data = decode_string(data)
    
#     cert_type, layer_one = decode_string(data)
#     signature = decode_string(layer_one)[0]
    
#     return signature, cert_type, data

class DSASignatureField(SignatureField):
    pass
#     def encode_dss_signature(r_value: bytes, s_value: bytes, cert_type: StrOrBytes = 'ssh-dss') ->bytes:
#     """Encodes a DSS signature fto the OpenSSH Certificate format

#     Args:
#         signature_r (bytes): The decoded signature R-value
#         signature_s (bytes): The decoded signature S-value
#         type (str): The certificate type, default: ssh-dss

#     Returns:
#         bytes: Byte string with the encoded certificate
#     """
#     return encode_string(
#             encode_string(cert_type) +
#             encode_string(
#                 long_to_bytes(r_value, 20) +
#                 long_to_bytes(s_value, 20)
#             )
#     )
    
# def decode_dss_signature(data: bytes) -> tuple:
#     """Decodes a DSS/DSA signature from the OpenSSH Certificate format

#     Args:
#         data (bytes): The byte block containing the signature

#     Returns:
#         tuple: Tuple containing the signature and remainder of the data
#     """
#     layer_one, data = decode_string(data)
    
#     cert_type, layer_one = decode_string(layer_one)
#     signature = decode_string(layer_one)[0]
#     r = bytes_to_long(signature[:20])
#     s = bytes_to_long(signature[20:])
    
#     return r, s, cert_type, data

class ECDSASignatureField(SignatureField):
    pass
#     def encode_ecdsa_signature(signature_r: bytes, signature_s: bytes, curve: StrOrBytes) -> bytes:
#     """Encodes an ECDSA signature to the OpenSSH Certificate format

#     Args:
#         signature_r (bytes): The decoded signature R-value
#         signature_s (bytes): The decoded signature S-value
#         curve (StrOrBytes): The EC-curve and hash used (e.g. ecdsa-sha2-nistp256)

#     Returns:
#         bytes: Bytestring with the encoded certificate
#     """
#     return encode_string(
#         encode_string(curve) +
#         encode_string(
#             encode_mpint(signature_r) +
#             encode_mpint(signature_s)
#         )
#     )
    
# def decode_ecdsa_signature(data: bytes) -> tuple:
#     """Decodes an ECDSA signature from the OpenSSH Certificate format

#     Args:
#         data (bytes): Block of bytes containing signature

#     Returns:
#         tuple: Tuple with signature and remainder of data
#     """
#     layer_one, data = decode_string(data)
    
#     curve, layer_one = decode_string(layer_one)
#     signature = decode_string(layer_one)[0]
#     r, signature = decode_mpint(signature)
#     s = decode_mpint(signature)[0]
    
#     return r, s, curve, data

class ED25519SignatureField(SignatureField):
    pass
    # def encode_ed25519_signature(signature: bytes, cert_type: StrOrBytes = 'ssh-ed25519') -> bytes:
    #     """Encodes an ED25519 signature to the OpenSSH Certificate format

    #     Args:
    #         signature (bytes): The signature data
    #         cert_type (str, bytes): The type, default ssh-ed25519

    #     Returns:
    #         _type_: Byte string with the encoded certificate
    #     """
    #     return encode_string( encode_string(cert_type) + encode_string(signature) )

    # def decode_ed25519_signature(data: bytes) -> tuple:
    #     """Decodes an ED25519 signature from the OpenSSH Certificate format

    #     Args:
    #         data (bytes): The block of bytes containing the signature

    #     Returns:
    #         tuple: Tuple containing the signature and remainder of the data
    #     """
    #     layer_one, data = decode_string(data)
        
    #     cert_type, layer_one = decode_string(layer_one)
    #     signature = decode_string(layer_one)[0]
        
    #     return signature, cert_type, data