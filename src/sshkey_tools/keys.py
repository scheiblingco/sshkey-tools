from typing import Union
from enum import Enum
from base64 import b64decode
from cryptography.hazmat.primitives import (
    serialization as _SERIALIZATION,
    hashes as _HASHES
)
from cryptography.hazmat.primitives.asymmetric import (
    rsa as _RSA,
    dsa as _DSA,
    ec as _ECDSA,
    ed25519 as _ED25519,
    padding as _PADDING
)

from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, _RSAPrivateKey
from cryptography.hazmat.backends.openssl.dsa import _DSAPublicKey, _DSAPrivateKey
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey, _EllipticCurvePrivateKey
from cryptography.hazmat.backends.openssl.ed25519 import _Ed25519PublicKey, _Ed25519PrivateKey

from .utils import (
    md5_fingerprint as _FP_MD5,
    sha256_fingerprint as _FP_SHA256,
    sha512_fingerprint as _FP_SHA512
)


from .exceptions import (
    InvalidCurveException,
    InvalidKeyException,
    InvalidHashException,
    InvalidKeyFormatException
)

PUBKEY_MAP = {
    _RSAPublicKey: "RSAPublicKey",
    _DSAPublicKey: "DSAPublicKey",
    _EllipticCurvePublicKey: "ECDSAPublicKey",
    _Ed25519PublicKey: "ED25519PublicKey"
}

PRIVKEY_MAP = {
    _RSAPrivateKey: "RSAPrivateKey",
    _DSAPrivateKey: "DSAPrivateKey",
    _EllipticCurvePrivateKey: "ECDSAPrivateKey",
    _Ed25519PrivateKey: "ED25519PrivateKey"
}

STR_OR_BYTES = Union[str, bytes]

PUBKEY_CLASSES = Union[
    _RSA.RSAPublicKey,
    _DSA.DSAPublicKey,
    _ECDSA.EllipticCurvePublicKey,
    _ED25519.Ed25519PublicKey
]

PRIVKEY_CLASSES = Union[
    _RSA.RSAPrivateKey,
    _DSA.DSAPrivateKey,
    _ECDSA.EllipticCurvePrivateKey,
    _ED25519.Ed25519PrivateKey
]

CURVE_OR_STRING = Union[str, _ECDSA.EllipticCurve]

ECDSA_HASHES = {
    'secp256r1': _HASHES.SHA256,
    'secp384r1': _HASHES.SHA384,
    'secp521r1': _HASHES.SHA512,
}

class RSA_ALGS(Enum):
    SHA1 = (
        'ssh-rsa',
        _HASHES.SHA1
    )
    SHA256 = (
        'rsa-sha2-256',
        _HASHES.SHA256
    )
    SHA512 = (
        'rsa-sha2-512',
        _HASHES.SHA512
    )

class ECDSA_CURVES(Enum):
    P256 = _ECDSA.SECP256R1
    P384 = _ECDSA.SECP384R1
    P521 = _ECDSA.SECP521R1
    
class FP_HASHES(Enum):
    MD5 = _FP_MD5
    SHA256 = _FP_SHA256
    SHA512 = _FP_SHA512

class PublicKey:
    def __init__(self, *args, **kwargs):
        self.key = kwargs.get('key', None)
        self.public_numbers = kwargs.get('public_numbers', None)
        self.comment = kwargs.get('comment', None)
        self.key_type = kwargs.get('key_type', None)
        self.serialized = kwargs.get('serialized', None)
        self.export_opts = {
            "pub_encoding": _SERIALIZATION.Encoding.OpenSSH,
            "pub_format": _SERIALIZATION.PublicFormat.OpenSSH,
        }


    @classmethod
    def from_class(
        cls,
        key_class: PUBKEY_CLASSES,
        comment: STR_OR_BYTES = None,
        key_type: STR_OR_BYTES = None
    ):
        try:
            return globals()[PUBKEY_MAP[key_class.__class__]](
                key_class,
                comment,
                key_type
            )
            
        except KeyError:
            raise InvalidKeyException(
                "Invalid public key"
            )

    @classmethod
    def from_string(cls, data: STR_OR_BYTES) -> 'PublicKey':
        if isinstance(data, str):
            data = data.encode('utf-8')

        split = data.split(b' ')
        comment = None
        if len(split) > 2:
            comment = split[2]

        return cls.from_class(
            _SERIALIZATION.load_ssh_public_key(
                b' '.join(split[:2])
            )
        )


    @classmethod
    def from_file(cls, file_name: str) -> 'PublicKey':
        with open(file_name, 'rb') as f:
            data = f.read()

        return cls.from_string(data)

    def serialize(self) -> bytes:
        return self.key.public_bytes(
            encoding=_SERIALIZATION.Encoding.OpenSSH,
            format=_SERIALIZATION.PublicFormat.OpenSSH
        )
        
    def get_fingerprint(self, hash: FP_HASHES = FP_HASHES.SHA256) -> str:
        return hash(self.to_bytes(
            key_id=False,
            encoded=False
        ))

    def to_bytes(self, key_id: bool = True, encoded: bool = True) -> bytes:
        if key_id and encoded:
            return self.serialize()
        
        if encoded and not key_id:
            return self.serialize()(b' ')[1]
        
        if key_id and not encoded:
            split = b' '.split(self.serialize())
            return b' '.join(split[0] + b64decode(split[1]))
        
        return b64decode(self.serialize().split(b' ')[1])

    def to_string(self) -> str:
        public_bytes = self.to_bytes()

        if self.comment is not None:
            public_bytes += b' ' + self.comment

        return public_bytes.decode('utf-8')

    def to_file(self, filename: str):
        with open(filename, 'w') as pubkey_file:
            pubkey_file.write(self.to_string())

class PrivateKey:
    def __init__(self, *args, **kwargs):
        self.key = kwargs.get('key', None)
        self.public_key = kwargs.get('public_key', None)
        self.private_numbers = kwargs.get('private_numbers', None)
        self.export_opts = {
            "encoding": _SERIALIZATION.Encoding.PEM,
            "format": _SERIALIZATION.PrivateFormat.OpenSSH,
            "encryption": _SERIALIZATION.BestAvailableEncryption,
        }

    @classmethod
    def from_class(cls, key_class: PRIVKEY_CLASSES):
        try:
            return globals()[PRIVKEY_MAP[key_class.__class__]](key_class)
        except KeyError:
            raise InvalidKeyException("Invalid private key")

    @classmethod
    def from_string(cls, data: STR_OR_BYTES, password: str = None) -> 'PrivateKey':
        if isinstance(data, str):
            data = data.encode('utf-8')

        private_key = _SERIALIZATION.load_ssh_private_key(
                data,
                password=password
        )

        return cls.from_class(private_key)

    @classmethod
    def from_file(cls, filename: str, password: str = None) -> 'PrivateKey':
        with open(filename, 'rb') as key_file:
            return cls.from_string(key_file.read(), password)

    def to_bytes(self, password: STR_OR_BYTES = None) -> bytes:
        if isinstance(password, str):
            password = password.encode('utf-8')

        encryption = _SERIALIZATION.NoEncryption()
        if password is not None:
            encryption = self.export_opts['encryption'](password)

        return self.key.private_bytes(
            self.export_opts['encoding'],
            self.export_opts['format'],
            encryption
        )

    def to_string(self, password: STR_OR_BYTES = None, encoding: str = 'utf-8') -> str:
        return self.to_bytes(password).decode(encoding)

    def to_file(self, filename: str, password: STR_OR_BYTES = None) -> None:
        with open(filename, 'wb') as key_file:
            key_file.write(
                self.to_bytes(
                    password
                )
            )

class RSAPublicKey(PublicKey):
    def __init__(
        self,
        key: _RSA.RSAPublicKey,
        comment: STR_OR_BYTES = None,
        key_type: STR_OR_BYTES = None,
        serialized: bytes = None
    ):
        super().__init__(
            key=key,
            comment=comment,
            key_type=key_type,
            public_numbers=key.public_numbers(),
            serialized=serialized
        )

    @classmethod
    def from_numbers(cls, e: int, n: int):
        return cls(
            key=_RSA.RSAPublicNumbers(e, n).public_key()
        )

class RSAPrivateKey(PrivateKey):
    def __init__(self, key: _RSA.RSAPrivateKey):
        super().__init__(
            key=key,
            public_key=RSAPublicKey(
                key.public_key()
            ),
            private_numbers=key.private_numbers()
        )

    @classmethod
    def from_numbers(
        cls,
        n: int,
        e: int,
        d: int,
        p: int = None,
        q: int = None,
        dmp1: int = None,
        dmq1: int = None,
        iqmp: int = None
    ):
        if None in (p, q):
            p, q = _RSA.rsa_recover_prime_factors(n, e, d)

        dmp1 = _RSA.rsa_crt_dmp1(d, p) if dmp1 is None else dmp1
        dmq1 = _RSA.rsa_crt_dmq1(d, q) if dmq1 is None else dmq1
        iqmp = _RSA.rsa_crt_iqmp(p, q) if iqmp is None else iqmp

        return cls(
            key=_RSA.RSAPrivateNumbers(
                public_numbers=_RSA.RSAPublicNumbers(e, n),
                p=p,
                q=q,
                d=d,
                dmp1=_RSA.rsa_crt_dmp1(d, p),
                dmq1=_RSA.rsa_crt_dmq1(d, q),
                iqmp=_RSA.rsa_crt_iqmp(p, q)
            ).private_key()
        )

    @classmethod
    def generate(
        cls,
        key_size: int = 4096,
        public_exponent: int = 65537
    ):
        return cls.from_class(
            _RSA.generate_private_key(
                public_exponent=public_exponent,
                key_size=key_size
            )
        )

    def sign(self, data: bytes, hash_alg: RSA_ALGS = RSA_ALGS.SHA512):
        return self.key.sign(
            data,
            _PADDING.PKCS1v15(),
            hash_alg.value[1]()
        )

class DSAPublicKey(PublicKey):
    def __init__(
        self,
        key: _DSA.DSAPublicKey,
        comment: STR_OR_BYTES = None,
        key_type: STR_OR_BYTES = None,
        serialized: bytes = None
    ):
        super().__init__(
            key=key,
            comment=comment,
            key_type=key_type,
            public_numbers=key.public_numbers(),
            serialized=serialized
        )
        self.parameters = key.parameters().parameter_numbers()

    @classmethod
    def from_numbers(
        cls,
        p: int,
        q: int,
        g: int,
        y: int
    ):
        return cls(
            key=_DSA.DSAPublicNumbers(
                y=y,
                parameter_numbers=_DSA.DSAParameterNumbers(
                    p=p,
                    q=q,
                    g=g
                )
            ).public_key()
        )

class DSAPrivateKey(PrivateKey):
    def __init__(self, key: _DSA.DSAPrivateKey):
        super().__init__(
            key=key,
            public_key=DSAPublicKey(
                key.public_key()
            ),
            private_numbers=key.private_numbers()
        )

    @classmethod
    def from_numbers(
        cls,
        p: int,
        q: int,
        g: int,
        y: int,
        x: int
    ):
        return cls(
            key=_DSA.DSAPrivateNumbers(
                public_numbers=_DSA.DSAPublicNumbers(
                    y=y,
                    parameter_numbers=_DSA.DSAParameterNumbers(
                        p=p,
                        q=q,
                        g=g
                    )
                ),
                x=x
            ).private_key()
        )

    @classmethod
    def generate(cls, key_size: int = 4096):
        return cls.from_class(
            _DSA.generate_private_key(
                key_size=key_size
            )
        )

    def sign(self, data: bytes):
       return self.key.sign(
            data,
            _HASHES.SHA1()
        )

class ECDSAPublicKey(PublicKey):
    def __init__(
        self,
        key: _ECDSA.EllipticCurvePublicKey,
        comment: STR_OR_BYTES = None,
        key_type: STR_OR_BYTES = None,
        serialized: bytes = None
    ):
        super().__init__(
            key=key,
            comment=comment,
            key_type=key_type,
            public_numbers=key.public_numbers(),
            serialized=serialized
        )

    @classmethod
    def from_numbers(
        cls,
        curve: CURVE_OR_STRING,
        x: int,
        y: int
    ):
        if not isinstance(curve, _ECDSA.EllipticCurve) and curve not in ECDSA_HASHES.keys():
            raise InvalidCurveException(f"Invalid curve, must be one of {', '.join(ECDSA_HASHES.keys())}")


        return cls(
            key=_ECDSA.EllipticCurvePublicNumbers(
                curve=ECDSA_HASHES[curve]() if isinstance(curve, str) else curve,
                x=x,
                y=y
            ).public_key()
        )

class ECDSAPrivateKey(PrivateKey):
    def __init__(self, key: _ECDSA.EllipticCurvePrivateKey):
        super().__init__(
            key=key,
            public_key=ECDSAPublicKey(
                key.public_key()
            ),
            private_numbers=key.private_numbers()
        )

    @classmethod
    def from_numbers(cls, curve: CURVE_OR_STRING, x: int, y: int, private_value: int):
        if not isinstance(curve, _ECDSA.EllipticCurve) and curve not in ECDSA_HASHES.keys():
            raise InvalidCurveException(f"Invalid curve, must be one of {', '.join(ECDSA_HASHES.keys())}")

        return cls(
            key=_ECDSA.EllipticCurvePrivateNumbers(
                public_numbers=_ECDSA.EllipticCurvePublicNumbers(
                    curve=ECDSA_HASHES[curve]() if isinstance(curve, str) else curve,
                    x=x,
                    y=y
                ),
                private_value=private_value
            ).private_key()
        )

    @classmethod
    def generate(cls, curve: ECDSA_CURVES = ECDSA_CURVES.P521):
        return cls.from_class(
            _ECDSA.generate_private_key(
                curve=curve.value
            )
        )

    def sign(self, data: bytes):
        curve = ECDSA_HASHES[self.key.curve.name]()
        return self.key.sign(
            data,
            _ECDSA.ECDSA(curve)
        )

class ED25519PublicKey(PublicKey):
    def __init__(
        self,
        key: _ED25519.Ed25519PublicKey,
        comment: STR_OR_BYTES = None,
        key_type: STR_OR_BYTES = None,
        serialized: bytes = None
    ):
        super().__init__(
            key=key,
            comment=comment,
            key_type=key_type,
            serialized=serialized
        )
        
    @classmethod
    def from_raw_bytes(cls, raw_bytes: bytes) -> 'ED25519PublicKey':
        return cls.from_class(
            _ED25519.Ed25519PublicKey.from_public_bytes(
                data=raw_bytes
            )
        )
        
    def raw_bytes(self):
        return self.key.public_bytes(
            encoding=_SERIALIZATION.Encoding.Raw,
            format=_SERIALIZATION.PublicFormat.Raw
        )

class ED25519PrivateKey(PrivateKey):
    def __init__(self, key: _ED25519.Ed25519PrivateKey):
        super().__init__(
            key=key,
            public_key=ED25519PublicKey(
                key.public_key()
            )
        )
    
    @classmethod
    def from_raw_bytes(cls, raw_bytes: bytes) -> 'ED25519PrivateKey':
        return cls.from_class(
            _ED25519.Ed25519PrivateKey.from_private_bytes(
                data=raw_bytes
            )
        )
    
    @classmethod
    def generate(cls):
        return cls.from_class(
            _ED25519.Ed25519PrivateKey.generate()
        )
        
    def raw_bytes(self):
        return self.key.private_bytes(
            encoding=_SERIALIZATION.Encoding.Raw,
            format=_SERIALIZATION.PrivateFormat.Raw,
            encryption_algorithm=_SERIALIZATION.NoEncryption()
        )
        
    def sign(self, data: bytes):
        return self.key.sign(data)