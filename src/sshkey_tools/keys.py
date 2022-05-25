"""
Classes for handling SSH public/private keys
"""
from typing import Union
from enum import Enum
from base64 import b64decode
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, _RSAPrivateKey
from cryptography.hazmat.backends.openssl.dsa import _DSAPublicKey, _DSAPrivateKey
from cryptography.hazmat.backends.openssl.ed25519 import _Ed25519PublicKey, _Ed25519PrivateKey
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePublicKey,
    _EllipticCurvePrivateKey
)
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

from . import exceptions as _EX
from .utils import (
    md5_fingerprint as _FP_MD5,
    sha256_fingerprint as _FP_SHA256,
    sha512_fingerprint as _FP_SHA512
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

ECDSA_HASHES = {
    'secp256r1': _HASHES.SHA256,
    'secp384r1': _HASHES.SHA384,
    'secp521r1': _HASHES.SHA512,
}

PubkeyClasses = Union[
    _RSA.RSAPublicKey,
    _DSA.DSAPublicKey,
    _ECDSA.EllipticCurvePublicKey,
    _ED25519.Ed25519PublicKey
]

PrivkeyClasses = Union[
    _RSA.RSAPrivateKey,
    _DSA.DSAPrivateKey,
    _ECDSA.EllipticCurvePrivateKey,
    _ED25519.Ed25519PrivateKey
]

class RsaAlgs(Enum):
    """
    RSA Algorithms
    """
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

class EcdsaCurves(Enum):
    """
    ECDSA Curves
    """
    P256 = _ECDSA.SECP256R1
    P384 = _ECDSA.SECP384R1
    P521 = _ECDSA.SECP521R1

class FingerprintHashes(Enum):
    """
    Fingerprint hashes
    """
    MD5 = _FP_MD5
    SHA256 = _FP_SHA256
    SHA512 = _FP_SHA512

class PublicKey:
    """
    Class for handling SSH public keys
    """
    def __init__(
        self,
        key: PrivkeyClasses = None,
        comment: Union[str, bytes] = None,
        **kwargs
    ) -> None:
        self.key = key
        self.comment = comment
        self.public_numbers = kwargs.get('public_numbers', None)
        self.key_type = kwargs.get('key_type', None)
        self.serialized = kwargs.get('serialized', None)

        self.export_opts = [
            _SERIALIZATION.Encoding.OpenSSH,
            _SERIALIZATION.PublicFormat.OpenSSH,
        ]


    @classmethod
    def from_class(
        cls,
        key_class: PubkeyClasses,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None
    ) -> 'PublicKey':
        """
        Creates a new SSH Public key from a cryptography class

        Args:
            key_class (PubkeyClasses): The cryptography class containing the public key
            comment (Union[str, bytes], optional): Comment to add to the key. Defaults to None.
            key_type (Union[str, bytes], optional): Manually specify the key type. Defaults to None.

        Raises:
            _EX.InvalidKeyException: The key you are trying to load is invalid

        Returns:
            PublicKey: Any of the PublicKey child classes
        """
        try:
            return globals()[PUBKEY_MAP[key_class.__class__]](
                key_class,
                comment,
                key_type
            )

        except KeyError:
            raise _EX.InvalidKeyException(
                "Invalid public key"
            ) from KeyError

    @classmethod
    def from_string(cls, data: Union[str, bytes]) -> 'PublicKey':
        """
        Loads an SSH public key from a string containing the data
        in OpenSSH format (SubjectPublickeyInfo)

        Args:
            data (Union[str, bytes]): The string or byte data containing the key

        Returns:
            PublicKey: Any of the PublicKey child classes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        split = data.split(b' ')
        comment = None
        if len(split) > 2:
            comment = split[2]

        return cls.from_class(
            key_class=_SERIALIZATION.load_ssh_public_key(
                b' '.join(split[:2])
            ),
            comment=comment
        )


    @classmethod
    def from_file(cls, path: str) -> 'PublicKey':
        """
        Loads an SSH Public key from a file

        Args:
            path (str): The path to the file

        Returns:
            PublicKey: Any of the PublicKey child classes
        """
        with open(path, 'rb') as file:
            data = file.read()

        return cls.from_string(data)

    def get_fingerprint(
        self,
        hash_method: FingerprintHashes = FingerprintHashes.SHA256
    ) -> str:
        """
        Generates a fingerprint of the public key

        Args:
            hash_method (FingerprintHashes, optional): Type of hash. Defaults to SHA256.

        Returns:
            str: The hash of the public key
        """
        return hash_method(self.raw_bytes())

    def serialize(self) -> bytes:
        """
        Serialize the key for storage in file or string

        Returns:
            bytes: The serialized key in OpenSSH format
        """
        return self.key.public_bytes(
            *self.export_opts
        )

    def raw_bytes(self) -> bytes:
        """
        Export the public key to a raw byte string

        Returns:
            bytes: The raw certificate bytes
        """
        return b64decode(self.serialize().split(b' ')[1])

    def to_string(self, encoding: str = 'utf-8') -> str:
        """
        Export the public key as a string

        Returns:
            str: The public key in OpenSSH format
            encoding(str, optional): The encoding of the file. Defaults to 'utf-8'.
        """
        public_bytes = self.serialize()

        if self.comment is not None:
            public_bytes += b' ' + self.comment

        return public_bytes.decode(encoding)

    def to_file(self, path: str, encoding: str = 'utf-8') -> None:
        """
        Export the public key to a file

        Args:
            path (str): The path of the file
            encoding(str, optional): The encoding of the file. Defaults to 'utf-8'.
        """
        with open(path, 'w', encoding=encoding) as pubkey_file:
            pubkey_file.write(self.to_string())

class PrivateKey:
    """
    Class for handling SSH Private keys
    """
    def __init__(
        self,
        key: PrivkeyClasses,
        public_key: PublicKey,
        **kwargs
    ) -> None:
        self.key = key
        self.public_key = public_key

        self.private_numbers = kwargs.get('private_numbers', None)
        self.export_opts = {
            "encoding": _SERIALIZATION.Encoding.PEM,
            "format": _SERIALIZATION.PrivateFormat.OpenSSH,
            "encryption": _SERIALIZATION.BestAvailableEncryption,
        }

    @classmethod
    def from_class(cls, key_class: PrivkeyClasses) -> 'PrivateKey':
        """
        Import an SSH Private key from a cryptography key class

        Args:
            key_class (PrivkeyClasses): A cryptography private key class

        Raises:
            _EX.InvalidKeyException: Invalid private key

        Returns:
            PrivateKey: One of the PrivateKey child classes
        """
        try:
            return globals()[PRIVKEY_MAP[key_class.__class__]](key_class)
        except KeyError:
            raise _EX.InvalidKeyException("Invalid private key") from KeyError

    @classmethod
    def from_string(
        cls,
        key_data: Union[str, bytes],
        password: Union[str, bytes] = None,
        encoding: str = 'utf-8'
    ) -> 'PrivateKey':
        """
        Loads an SSH private key from a string containing the key data

        Args:
            key_data (Union[str, bytes]): The string containing the key data
            password (str, optional): The password for the private key. Defaults to None.
            encoding(str, optional): The encoding of the file. Defaults to 'utf-8'.

        Returns:
            PrivateKey: Any of the PrivateKey child classes
        """
        if isinstance(key_data, str):
            key_data = key_data.encode(encoding)

        if isinstance(password, str):
            password = password.encode(encoding)

        private_key = _SERIALIZATION.load_ssh_private_key(
                key_data,
                password=password
        )

        return cls.from_class(private_key)

    @classmethod
    def from_file(
        cls,
        path: str,
        password: Union[str, bytes] = None,
        encoding: str = 'utf-8'
    ) -> 'PrivateKey':
        """
        Loads an SSH private key from a file

        Args:
            path (str): The path to the file
            password (str, optional): The encryption password. Defaults to None.
            encoding(str, optional): The encoding of the file. Defaults to 'utf-8'.

        Returns:
            PrivateKey: Any of the PrivateKey child classes
        """
        with open(path, 'rb', encoding=encoding) as key_file:
            return cls.from_string(key_file.read(), password)

    def to_bytes(self, password: Union[str, bytes] = None) -> bytes:
        """
        Exports the private key to a byte string

        Args:
            password (Union[str, bytes], optional): The password to set for the key.
                                                    Defaults to None.

        Returns:
            bytes: The private key in PEM format
        """
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

    def to_string(self, password: Union[str, bytes] = None, encoding: str = 'utf-8') -> str:
        """
        Exports the private key to a string

        Args:
            password (Union[str, bytes], optional): The password to set for the key.
                                                    Defaults to None.
            encoding (str, optional): The encoding of the string. Defaults to 'utf-8'.
        Returns:
            bytes: The private key in PEM format
        """

        return self.to_bytes(password).decode(encoding)

    def to_file(
        self,
        path: str,
        password: Union[str, bytes] = None,
        encoding: str = 'utf-8'
    ) -> None:
        """
        Exports the private key to a file

        Args:
            password (Union[str, bytes], optional): The password to set for the key.
                                                    Defaults to None.

        Returns:
            bytes: The private key in PEM format
        """
        with open(path, 'w', encoding=encoding) as key_file:
            key_file.write(
                self.to_string(
                    password,
                    encoding
                )
            )

class RSAPublicKey(PublicKey):
    """
    Class for holding RSA public keys
    """
    def __init__(
        self,
        key: _RSA.RSAPublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
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
    # pylint: disable=invalid-name
    def from_numbers(cls, e: int, n: int) -> 'RSAPublicKey':
        """
        Loads an RSA Public Key from the public numbers e and n

        Args:
            e (int): e-value
            n (int): n-value

        Returns:
            RSAPublicKey: _description_
        """
        return cls(
            key=_RSA.RSAPublicNumbers(e, n).public_key()
        )

class RSAPrivateKey(PrivateKey):
    """
    Class for holding RSA private keys
    """
    def __init__(self, key: _RSA.RSAPrivateKey):
        super().__init__(
            key=key,
            public_key=RSAPublicKey(
                key.public_key()
            ),
            private_numbers=key.private_numbers()
        )

    @classmethod
    # pylint: disable=invalid-name,too-many-arguments
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
    ) -> 'RSAPrivateKey':
        """
        Load an RSA private key from numbers

        Args:
            n (int): The public modulus (n)
            e (int): The public exponent (e)
            d (int): The private exponent (d)
            p (int, optional): One of two primes (p) composing the public modulus.
                               Automatically generates if not provided.
            q (int, optional): One of two primes (q) composing the public modulus.
                               Automatically generates if not provided
            dmp1 (int, optional): Chinese remainder theorem coefficient to speed up operations
                                  Calculated as d mod (p-1)
                                  Automatically generates if not provided
            dmq1 (int, optional): Chinese remainder theorem coefficient to speed up operations
                                  Calculated as d mod(q-1)
                                  Automatically generates if not provided
            iqmp (int, optional): Chinese remainder theorem coefficient to speed up operations
                                  Calculated as q^-1 mod p
                               Automatically generates if not provided

        Returns:
            RSAPrivateKey: An instance of RSAPrivateKey
        """
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
    ) -> 'RSAPrivateKey':
        """
        Generates a new RSA private key

        Args:
            key_size (int, optional): The number of bytes for the key. Defaults to 4096.
            public_exponent (int, optional): The public exponent to use. Defaults to 65537.

        Returns:
            RSAPrivateKey: Instance of RSAPrivateKey
        """
        return cls.from_class(
            _RSA.generate_private_key(
                public_exponent=public_exponent,
                key_size=key_size
            )
        )

    def sign(self, data: bytes, hash_alg: RsaAlgs = RsaAlgs.SHA512) -> bytes:
        """
        Signs a block of data and returns the signature

        Args:
            data (bytes): Block of byte data to sign
            hash_alg (RsaAlgs, optional): Algorithm to use for hashing.
                                          Defaults to SHA512.

        Returns:
            bytes: The signature bytes
        """
        return self.key.sign(
            data,
            _PADDING.PKCS1v15(),
            hash_alg.value[1]()
        )

class DSAPublicKey(PublicKey):
    """
    Class for holding DSA public keys
    """
    def __init__(
        self,
        key: _DSA.DSAPublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
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
    # pylint: disable=invalid-name
    def from_numbers(
        cls,
        p: int,
        q: int,
        g: int,
        y: int
    ) -> 'DSAPublicKey':
        """
        Create a DSA public key from public numbers and parameters

        Args:
            p (int): P parameter, the prime modulus
            q (int): Q parameter, the order of the subgroup
            g (int): G parameter, the generator
            y (int): The public number Y

        Returns:
            DSAPublicKey: An instance of DSAPublicKey
        """
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
    """
    Class for holding DSA private keys
    """
    def __init__(self, key: _DSA.DSAPrivateKey):
        super().__init__(
            key=key,
            public_key=DSAPublicKey(
                key.public_key()
            ),
            private_numbers=key.private_numbers()
        )

    @classmethod
    # pylint: disable=invalid-name,too-many-arguments
    def from_numbers(
        cls,
        p: int,
        q: int,
        g: int,
        y: int,
        x: int
    ) -> 'DSAPrivateKey':
        """
        Creates a new DSAPrivateKey object from parameters and public/private numbers

        Args:
            p (int): P parameter, the prime modulus
            q (int): Q parameter, the order of the subgroup
            g (int): G parameter, the generator
            y (int): The public number Y
            x (int): The private number X

        Returns:
            _type_: _description_
        """
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
    def generate(cls, key_size: int = 4096) -> 'DSAPrivateKey':
        """
        Generate a new DSA private key

        Args:
            key_size (int, optional): Number of key bytes. Defaults to 4096.

        Returns:
            DSAPrivateKey: An instance of DSAPrivateKey
        """
        return cls.from_class(
            _DSA.generate_private_key(
                key_size=key_size
            )
        )

    def sign(self, data: bytes):
        """
        Signs a block of data and returns the signature

        Args:
            data (bytes): Block of byte data to sign

        Returns:
            bytes: The signature bytes
        """
        return self.key.sign(
            data,
            _HASHES.SHA1()
        )

class ECDSAPublicKey(PublicKey):
    """
    Class for holding ECDSA public keys
    """
    def __init__(
        self,
        key: _ECDSA.EllipticCurvePublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
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
    #pylint: disable=invalid-name
    def from_numbers(
        cls,
        curve: Union[str, _ECDSA.EllipticCurve],
        x: int,
        y: int
    ) -> 'ECDSAPublicKey':
        """
        Create an ECDSA public key from public numbers and parameters

        Args:
            curve Union[str, _ECDSA.EllipticCurve]: Curve used by the key
            x (int): The affine X component of the public point
            y (int): The affine Y component of the public point

        Returns:
            ECDSAPublicKey: An instance of ECDSAPublicKey
        """
        if not isinstance(curve, _ECDSA.EllipticCurve) and curve not in ECDSA_HASHES:
            raise _EX.InvalidCurveException(
                f"Invalid curve, must be one of {', '.join(ECDSA_HASHES.keys())}"
            )

        if isinstance(curve, _ECDSA.EllipticCurve):
            curve = curve.name

        return cls(
            key=_ECDSA.EllipticCurvePublicNumbers(
                curve=ECDSA_HASHES[curve]() if isinstance(curve, str) else curve,
                x=x,
                y=y
            ).public_key()
        )

class ECDSAPrivateKey(PrivateKey):
    """
    Class for holding ECDSA private keys
    """
    def __init__(self, key: _ECDSA.EllipticCurvePrivateKey):
        super().__init__(
            key=key,
            public_key=ECDSAPublicKey(
                key.public_key()
            ),
            private_numbers=key.private_numbers()
        )

    @classmethod
    #pylint: disable=invalid-name
    def from_numbers(
        cls,
        curve: Union[str, _ECDSA.EllipticCurve],
        x: int,
        y: int,
        private_value: int
    ):
        """
        Creates a new ECDSAPrivateKey object from parameters and public/private numbers

        Args:
            curve Union[str, _ECDSA.EllipticCurve]: Curve used by the key
            x (int): The affine X component of the public point
            y (int): The affine Y component of the public point
            private_value (int): The private value

        Returns:
            _type_: _description_
        """
        if not isinstance(curve, _ECDSA.EllipticCurve) and curve not in ECDSA_HASHES:
            raise _EX.InvalidCurveException(
                f"Invalid curve, must be one of {', '.join(ECDSA_HASHES.keys())}"
            )

        if isinstance(curve, _ECDSA.EllipticCurve):
            curve = curve.name

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
    def generate(cls, curve: EcdsaCurves = EcdsaCurves.P521):
        """
        Generate a new ECDSA private key

        Args:
            curve (EcdsaCurves): Which curve to use. Default secp521r1

        Returns:
            ECDSAPrivateKey: An instance of ECDSAPrivateKey
        """
        return cls.from_class(
            _ECDSA.generate_private_key(
                curve=curve.value
            )
        )

    def sign(self, data: bytes):
        """
        Signs a block of data and returns the signature

        Args:
            data (bytes): Block of byte data to sign

        Returns:
            bytes: The signature bytes
        """
        curve = ECDSA_HASHES[self.key.curve.name]()
        return self.key.sign(
            data,
            _ECDSA.ECDSA(curve)
        )

class ED25519PublicKey(PublicKey):
    """
    Class for holding ED25519 public keys
    """
    def __init__(
        self,
        key: _ED25519.Ed25519PublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
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
        """
        Load an ED25519 public key from raw bytes

        Args:
            raw_bytes (bytes): The raw bytes of the key

        Returns:
            ED25519PublicKey: Instance of ED25519PublicKey
        """
        return cls.from_class(
            _ED25519.Ed25519PublicKey.from_public_bytes(
                data=raw_bytes
            )
        )

class ED25519PrivateKey(PrivateKey):
    """
    Class for holding ED25519 private keys
    """
    def __init__(self, key: _ED25519.Ed25519PrivateKey):
        super().__init__(
            key=key,
            public_key=ED25519PublicKey(
                key.public_key()
            )
        )

    @classmethod
    def from_raw_bytes(cls, raw_bytes: bytes) -> 'ED25519PrivateKey':
        """
        Load an ED25519 private key from raw bytes

        Args:
            raw_bytes (bytes): The raw bytes of the key

        Returns:
            ED25519PrivateKey: Instance of ED25519PrivateKey
        """
        return cls.from_class(
            _ED25519.Ed25519PrivateKey.from_private_bytes(
                data=raw_bytes
            )
        )

    @classmethod
    def generate(cls) -> 'ED25519PrivateKey':
        """
        Generates a new ED25519 Private Key

        Returns:
            ED25519PrivateKey: Instance of ED25519PrivateKey
        """
        return cls.from_class(
            _ED25519.Ed25519PrivateKey.generate()
        )

    def raw_bytes(self) -> bytes:
        """
        Export the raw key bytes

        Returns:
            bytes: The key bytes
        """
        return self.key.private_bytes(
            encoding=_SERIALIZATION.Encoding.Raw,
            format=_SERIALIZATION.PrivateFormat.Raw,
            encryption_algorithm=_SERIALIZATION.NoEncryption()
        )

    def sign(self, data: bytes):
        """
        Signs a block of data and returns the signature

        Args:
            data (bytes): Block of byte data to sign

        Returns:
            bytes: The signature bytes
        """
        return self.key.sign(data)
