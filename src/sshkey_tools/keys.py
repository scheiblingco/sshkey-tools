"""
Classes for handling SSH public/private keys
"""
from base64 import b64decode
from enum import Enum
from struct import unpack
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.dsa import _DSAPrivateKey, _DSAPublicKey
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey,
    _EllipticCurvePublicKey,
)
from cryptography.hazmat.backends.openssl.ed25519 import (
    _Ed25519PrivateKey,
    _Ed25519PublicKey,
)
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from cryptography.hazmat.primitives import hashes as _HASHES
from cryptography.hazmat.primitives import serialization as _SERIALIZATION
from cryptography.hazmat.primitives.asymmetric import dsa as _DSA
from cryptography.hazmat.primitives.asymmetric import ec as _ECDSA
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ED25519
from cryptography.hazmat.primitives.asymmetric import padding as _PADDING
from cryptography.hazmat.primitives.asymmetric import rsa as _RSA

from . import exceptions as _EX
from .utils import ensure_bytestring, ensure_string
from .utils import md5_fingerprint as _FP_MD5
from .utils import sha256_fingerprint as _FP_SHA256
from .utils import sha512_fingerprint as _FP_SHA512

PUBKEY_MAP = {
    _RSAPublicKey: "RsaPublicKey",
    _DSAPublicKey: "DsaPublicKey",
    _EllipticCurvePublicKey: "EcdsaPublicKey",
    _Ed25519PublicKey: "Ed25519PublicKey",
}

PRIVKEY_MAP = {
    _RSAPrivateKey: "RsaPrivateKey",
    _DSAPrivateKey: "DsaPrivateKey",
    _EllipticCurvePrivateKey: "EcdsaPrivateKey",
    # trunk-ignore(gitleaks/generic-api-key)
    _Ed25519PrivateKey: "Ed25519PrivateKey",
}

ECDSA_HASHES = {
    "secp256r1": _HASHES.SHA256,
    "secp384r1": _HASHES.SHA384,
    "secp521r1": _HASHES.SHA512,
}

PubkeyClasses = Union[
    _RSA.RSAPublicKey,
    _DSA.DSAPublicKey,
    _ECDSA.EllipticCurvePublicKey,
    _ED25519.Ed25519PublicKey,
]

PrivkeyClasses = Union[
    _RSA.RSAPrivateKey,
    _DSA.DSAPrivateKey,
    _ECDSA.EllipticCurvePrivateKey,
    _ED25519.Ed25519PrivateKey,
]


class RsaAlgs(Enum):
    """
    RSA Algorithms

    Values:
        SHA1
        SHA256
        SHA512
    """

    SHA1 = ("ssh-rsa", _HASHES.SHA1)
    SHA256 = ("rsa-sha2-256", _HASHES.SHA256)
    SHA512 = ("rsa-sha2-512", _HASHES.SHA512)


class EcdsaCurves(Enum):
    """
    ECDSA Curves

    Values:
        P256
        P384
        P521
    """

    P256 = _ECDSA.SECP256R1
    P384 = _ECDSA.SECP384R1
    P521 = _ECDSA.SECP521R1


class FingerprintHashes(Enum):
    """
    Fingerprint hashes
    Values:
        MD5
        SHA256
        SHA512
    """

    MD5 = _FP_MD5
    SHA256 = _FP_SHA256
    SHA512 = _FP_SHA512


class PublicKey:
    """
    Class for handling SSH public keys
    """

    def __init__(
        self, key: PrivkeyClasses = None, comment: Union[str, bytes] = None, **kwargs
    ) -> None:
        self.key = key
        self.comment = comment
        self.public_numbers = kwargs.get("public_numbers", None)
        self.key_type = kwargs.get("key_type", None)
        self.serialized = kwargs.get("serialized", None)

        self.export_opts = [
            _SERIALIZATION.Encoding.OpenSSH,
            _SERIALIZATION.PublicFormat.OpenSSH,
        ]

    @classmethod
    def from_class(
        cls,
        key_class: PubkeyClasses,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
    ) -> "PublicKey":
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
                key_class, comment, key_type
            )

        except KeyError:
            raise _EX.InvalidKeyException("Invalid public key") from KeyError

    @classmethod
    def from_string(
        cls, data: Union[str, bytes], encoding: str = "utf-8"
    ) -> "PublicKey":
        """
        Loads an SSH public key from a string containing the data
        in OpenSSH format (SubjectPublickeyInfo)

        Args:
            data (Union[str, bytes]): The string or byte data containing the key

        Returns:
            PublicKey: Any of the PublicKey child classes
        """
        split = ensure_bytestring(data, encoding).split(b" ")
        comment = None
        if len(split) > 2:
            comment = split[2]

        return cls.from_class(
            key_class=_SERIALIZATION.load_ssh_public_key(b" ".join(split[:2])),
            comment=comment,
        )

    @classmethod
    def from_file(cls, path: str) -> "PublicKey":
        """
        Loads an SSH Public key from a file

        Args:
            path (str): The path to the file

        Returns:
            PublicKey: Any of the PublicKey child classes
        """
        with open(path, "rb") as file:
            data = file.read()

        return cls.from_string(data)

    @classmethod
    # pylint: disable=broad-except
    def from_bytes(cls, data: bytes) -> "PublicKey":
        """
        Loads a public key from byte data

        Args:
            data (bytes): The bytestring containing the public key

        Raises:
            _EX.InvalidKeyException: Invalid data input

        Returns:
            PublicKey: PublicKey subclass depending on the key type
        """
        for key_class in PUBKEY_MAP.values():
            try:
                key = globals()[key_class].from_raw_bytes(data)
                return key
            except Exception:
                pass

        raise _EX.InvalidKeyException("Invalid public key")

    def get_fingerprint(
        self, hash_method: FingerprintHashes = FingerprintHashes.SHA256
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
        return self.key.public_bytes(*self.export_opts)

    def raw_bytes(self) -> bytes:
        """
        Export the public key to a raw byte string

        Returns:
            bytes: The raw certificate bytes
        """
        return b64decode(self.serialize().split(b" ")[1])

    def to_string(self, encoding: str = "utf-8") -> str:
        """
        Export the public key as a string

        Returns:
            str: The public key in OpenSSH format
            encoding(str, optional): The encoding of the file. Defaults to 'utf-8'.
        """
        return " ".join(
            [
                ensure_string(self.serialize(), encoding),
                ensure_string(getattr(self, "comment", ""), encoding),
            ]
        )

    def to_file(self, path: str, encoding: str = "utf-8") -> None:
        """
        Export the public key to a file

        Args:
            path (str): The path of the file
            encoding(str, optional): The encoding of the file. Defaults to 'utf-8'.
        """
        with open(path, "w", encoding=encoding) as pubkey_file:
            pubkey_file.write(self.to_string())


class PrivateKey:
    """
    Class for handling SSH Private keys
    """

    def __init__(self, key: PrivkeyClasses, public_key: PublicKey, **kwargs) -> None:
        self.key = key
        self.public_key = public_key

        self.private_numbers = kwargs.get("private_numbers", None)
        self.export_opts = {
            "encoding": _SERIALIZATION.Encoding.PEM,
            "format": _SERIALIZATION.PrivateFormat.OpenSSH,
            "encryption": _SERIALIZATION.BestAvailableEncryption,
        }

    @classmethod
    def from_class(cls, key_class: PrivkeyClasses) -> "PrivateKey":
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
        encoding: str = "utf-8",
    ) -> "PrivateKey":
        """
        Loads an SSH private key from a string containing the key data

        Args:
            key_data (Union[str, bytes]): The string containing the key data
            password (str, optional): The password for the private key. Defaults to None.
            encoding(str, optional): The encoding of the file. Defaults to 'utf-8'.

        Returns:
            PrivateKey: Any of the PrivateKey child classes
        """
        key_data, password = ensure_bytestring((key_data, password), encoding=encoding)
        private_key = _SERIALIZATION.load_ssh_private_key(key_data, password=password)

        return cls.from_class(private_key)

    @classmethod
    def from_file(
        cls,
        path: str,
        password: Union[str, bytes] = None,
    ) -> "PrivateKey":
        """
        Loads an SSH private key from a file

        Args:
            path (str): The path to the file
            password (str, optional): The encryption password. Defaults to None.
            encoding(str, optional): The encoding of the file. Defaults to 'utf-8'.

        Returns:
            PrivateKey: Any of the PrivateKey child classes
        """
        with open(path, "rb") as key_file:
            return cls.from_string(key_file.read(), password)

    def get_fingerprint(
        self, hash_method: FingerprintHashes = FingerprintHashes.SHA256
    ) -> str:
        """
        Generates a fingerprint of the private key

        Args:
            hash_method (FingerprintHashes, optional): Type of hash. Defaults to SHA256.

        Returns:
            str: The hash of the private key
        """
        return self.public_key.get_fingerprint(hash_method)

    def to_bytes(self, password: Union[str, bytes] = None) -> bytes:
        """
        Exports the private key to a byte string

        Args:
            password (Union[str, bytes], optional): The password to set for the key.
                                                    Defaults to None.

        Returns:
            bytes: The private key in PEM format
        """
        password = ensure_bytestring(password)

        encryption = _SERIALIZATION.NoEncryption()
        if password is not None:
            encryption = self.export_opts["encryption"](password)

        return self.key.private_bytes(
            self.export_opts["encoding"], self.export_opts["format"], encryption
        )

    def to_string(
        self, password: Union[str, bytes] = None, encoding: str = "utf-8"
    ) -> str:
        """
        Exports the private key to a string

        Args:
            password (Union[str, bytes], optional): The password to set for the key.
                                                    Defaults to None.
            encoding (str, optional): The encoding of the string. Defaults to 'utf-8'.
        Returns:
            bytes: The private key in PEM format
        """

        return ensure_string(self.to_bytes(password), encoding)

    def to_file(
        self, path: str, password: Union[str, bytes] = None, encoding: str = "utf-8"
    ) -> None:
        """
        Exports the private key to a file

        Args:
            password (Union[str, bytes], optional): The password to set for the key.
                                                    Defaults to None.

        Returns:
            bytes: The private key in PEM format
        """
        with open(path, "w", encoding=encoding) as key_file:
            key_file.write(self.to_string(password, encoding))


class RsaPublicKey(PublicKey):
    """
    Class for holding RSA public keys
    """

    def __init__(
        self,
        key: _RSA.RSAPublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
        serialized: bytes = None,
    ):
        super().__init__(
            key=key,
            comment=comment,
            key_type=key_type,
            public_numbers=key.public_numbers(),
            serialized=serialized,
        )

    @classmethod
    # pylint: disable=invalid-name
    def from_numbers(cls, e: int, n: int) -> "RsaPublicKey":
        """
        Loads an RSA Public Key from the public numbers e and n

        Args:
            e (int): e-value
            n (int): n-value

        Returns:
            RsaPublicKey: _description_
        """
        return cls(key=_RSA.RSAPublicNumbers(e, n).public_key())

    def verify(
        self, data: bytes, signature: bytes, hash_alg: RsaAlgs = RsaAlgs.SHA512
    ) -> None:
        """
        Verifies a signature

        Args:
            data (bytes): The data to verify
            signature (bytes): The signature to verify
            hash_method (HashMethods): The hash method to use

        Raises:
            Raises a sshkey_tools.exceptions.InvalidSignatureException if the signature is invalid
        """
        try:
            return self.key.verify(
                signature, data, _PADDING.PKCS1v15(), hash_alg.value[1]()
            )
        except InvalidSignature:
            raise _EX.InvalidSignatureException(
                "The signature is invalid for the given data"
            ) from InvalidSignature


class RsaPrivateKey(PrivateKey):
    """
    Class for holding RSA private keys
    """

    def __init__(self, key: _RSA.RSAPrivateKey):
        super().__init__(
            key=key,
            public_key=RsaPublicKey(key.public_key()),
            private_numbers=key.private_numbers(),
        )

    @classmethod
    # pylint: disable=invalid-name,too-many-arguments
    def from_numbers(
        cls,
        e: int,
        n: int,
        d: int,
        p: int = None,
        q: int = None,
        dmp1: int = None,
        dmq1: int = None,
        iqmp: int = None,
    ) -> "RsaPrivateKey":
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
            RsaPrivateKey: An instance of RsaPrivateKey
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
                iqmp=_RSA.rsa_crt_iqmp(p, q),
            ).private_key()
        )

    @classmethod
    def generate(
        cls, key_size: int = 4096, public_exponent: int = 65537
    ) -> "RsaPrivateKey":
        """
        Generates a new RSA private key

        Args:
            key_size (int, optional): The number of bytes for the key. Defaults to 4096.
            public_exponent (int, optional): The public exponent to use. Defaults to 65537.

        Returns:
            RsaPrivateKey: Instance of RsaPrivateKey
        """
        return cls.from_class(
            _RSA.generate_private_key(
                public_exponent=public_exponent, key_size=key_size
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
        return self.key.sign(data, _PADDING.PKCS1v15(), hash_alg.value[1]())


class DsaPublicKey(PublicKey):
    """
    Class for holding DSA public keys
    """

    def __init__(
        self,
        key: _DSA.DSAPublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
        serialized: bytes = None,
    ):
        super().__init__(
            key=key,
            comment=comment,
            key_type=key_type,
            public_numbers=key.public_numbers(),
            serialized=serialized,
        )
        self.parameters = key.parameters().parameter_numbers()

    @classmethod
    # pylint: disable=invalid-name
    def from_numbers(cls, p: int, q: int, g: int, y: int) -> "DsaPublicKey":
        """
        Create a DSA public key from public numbers and parameters

        Args:
            p (int): P parameter, the prime modulus
            q (int): Q parameter, the order of the subgroup
            g (int): G parameter, the generator
            y (int): The public number Y

        Returns:
            DsaPublicKey: An instance of DsaPublicKey
        """
        return cls(
            key=_DSA.DSAPublicNumbers(
                y=y, parameter_numbers=_DSA.DSAParameterNumbers(p=p, q=q, g=g)
            ).public_key()
        )

    def verify(self, data: bytes, signature: bytes) -> None:
        """
        Verifies a signature

        Args:
            data (bytes): The data to verify
            signature (bytes): The signature to verify

        Raises:
            Raises an sshkey_tools.exceptions.InvalidSignatureException if the signature is invalid
        """
        try:
            return self.key.verify(signature, data, _HASHES.SHA1())
        except InvalidSignature:
            raise _EX.InvalidSignatureException(
                "The signature is invalid for the given data"
            ) from InvalidSignature


class DsaPrivateKey(PrivateKey):
    """
    Class for holding DSA private keys
    """

    def __init__(self, key: _DSA.DSAPrivateKey):
        super().__init__(
            key=key,
            public_key=DsaPublicKey(key.public_key()),
            private_numbers=key.private_numbers(),
        )

    @classmethod
    # pylint: disable=invalid-name,too-many-arguments
    def from_numbers(cls, p: int, q: int, g: int, y: int, x: int) -> "DsaPrivateKey":
        """
        Creates a new DsaPrivateKey object from parameters and public/private numbers

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
                    y=y, parameter_numbers=_DSA.DSAParameterNumbers(p=p, q=q, g=g)
                ),
                x=x,
            ).private_key()
        )

    @classmethod
    def generate(cls) -> "DsaPrivateKey":
        """
        Generate a new DSA private key
        Key size is fixed since OpenSSH only supports 1024-bit DSA keys

        Returns:
            DsaPrivateKey: An instance of DsaPrivateKey
        """
        return cls.from_class(_DSA.generate_private_key(key_size=1024))

    def sign(self, data: bytes):
        """
        Signs a block of data and returns the signature

        Args:
            data (bytes): Block of byte data to sign

        Returns:
            bytes: The signature bytes
        """
        return self.key.sign(data, _HASHES.SHA1())


class EcdsaPublicKey(PublicKey):
    """
    Class for holding ECDSA public keys
    """

    def __init__(
        self,
        key: _ECDSA.EllipticCurvePublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
        serialized: bytes = None,
    ):
        super().__init__(
            key=key,
            comment=comment,
            key_type=key_type,
            public_numbers=key.public_numbers(),
            serialized=serialized,
        )

    @classmethod
    # pylint: disable=invalid-name
    def from_numbers(
        cls, curve: Union[str, _ECDSA.EllipticCurve], x: int, y: int
    ) -> "EcdsaPublicKey":
        """
        Create an ECDSA public key from public numbers and parameters

        Args:
            curve Union[str, _ECDSA.EllipticCurve]: Curve used by the key
            x (int): The affine X component of the public point
            y (int): The affine Y component of the public point

        Returns:
            EcdsaPublicKey: An instance of EcdsaPublicKey
        """
        if not isinstance(curve, _ECDSA.EllipticCurve) and curve not in ECDSA_HASHES:
            raise _EX.InvalidCurveException(
                f"Invalid curve, must be one of {', '.join(ECDSA_HASHES.keys())}"
            )

        if isinstance(curve, _ECDSA.EllipticCurve):
            curve = curve.name

        return cls(
            key=_ECDSA.EllipticCurvePublicNumbers(
                curve=getattr(_ECDSA, curve.upper())(),
                x=x,
                y=y,
            ).public_key()
        )

    def verify(self, data: bytes, signature: bytes) -> None:
        """
        Verifies a signature

        Args:
            data (bytes): The data to verify
            signature (bytes): The signature to verify

        Raises:
            Raises an sshkey_tools.exceptions.InvalidSignatureException if the signature is invalid
        """
        try:
            curve_hash = ECDSA_HASHES[self.key.curve.name]()
            return self.key.verify(signature, data, _ECDSA.ECDSA(curve_hash))
        except InvalidSignature:
            raise _EX.InvalidSignatureException(
                "The signature is invalid for the given data"
            ) from InvalidSignature


class EcdsaPrivateKey(PrivateKey):
    """
    Class for holding ECDSA private keys
    """

    def __init__(self, key: _ECDSA.EllipticCurvePrivateKey):
        super().__init__(
            key=key,
            public_key=EcdsaPublicKey(key.public_key()),
            private_numbers=key.private_numbers(),
        )

    @classmethod
    # pylint: disable=invalid-name
    def from_numbers(
        cls, curve: Union[str, _ECDSA.EllipticCurve], x: int, y: int, private_value: int
    ):
        """
        Creates a new EcdsaPrivateKey object from parameters and public/private numbers

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
                    curve=getattr(_ECDSA, curve.upper())(),
                    x=x,
                    y=y,
                ),
                private_value=private_value,
            ).private_key()
        )

    @classmethod
    def generate(cls, curve: EcdsaCurves = EcdsaCurves.P521):
        """
        Generate a new ECDSA private key

        Args:
            curve (EcdsaCurves): Which curve to use. Default secp521r1

        Returns:
            EcdsaPrivateKey: An instance of EcdsaPrivateKey
        """
        return cls.from_class(_ECDSA.generate_private_key(curve=curve.value))

    def sign(self, data: bytes):
        """
        Signs a block of data and returns the signature

        Args:
            data (bytes): Block of byte data to sign

        Returns:
            bytes: The signature bytes
        """
        curve_hash = ECDSA_HASHES[self.key.curve.name]()
        return self.key.sign(data, _ECDSA.ECDSA(curve_hash))


class Ed25519PublicKey(PublicKey):
    """
    Class for holding ED25519 public keys
    """

    def __init__(
        self,
        key: _ED25519.Ed25519PublicKey,
        comment: Union[str, bytes] = None,
        key_type: Union[str, bytes] = None,
        serialized: bytes = None,
    ):
        super().__init__(
            key=key, comment=comment, key_type=key_type, serialized=serialized
        )

    @classmethod
    def from_raw_bytes(cls, raw_bytes: bytes) -> "Ed25519PublicKey":
        """
        Load an ED25519 public key from raw bytes

        Args:
            raw_bytes (bytes): The raw bytes of the key

        Returns:
            Ed25519PublicKey: Instance of Ed25519PublicKey
        """
        if b"ssh-ed25519" in raw_bytes:
            id_length = unpack(">I", raw_bytes[:4])[0] + 8
            raw_bytes = raw_bytes[id_length:]

        return cls.from_class(
            _ED25519.Ed25519PublicKey.from_public_bytes(data=raw_bytes)
        )

    def verify(self, data: bytes, signature: bytes) -> None:
        """
        Verifies a signature

        Args:
            data (bytes): The data to verify
            signature (bytes): The signature to verify

        Raises:
            Raises an sshkey_tools.exceptions.InvalidSignatureException if the signature is invalid
        """
        try:
            return self.key.verify(signature, data)
        except InvalidSignature:
            raise _EX.InvalidSignatureException(
                "The signature is invalid for the given data"
            ) from InvalidSignature


class Ed25519PrivateKey(PrivateKey):
    """
    Class for holding ED25519 private keys
    """

    def __init__(self, key: _ED25519.Ed25519PrivateKey):
        super().__init__(key=key, public_key=Ed25519PublicKey(key.public_key()))

    @classmethod
    def from_raw_bytes(cls, raw_bytes: bytes) -> "Ed25519PrivateKey":
        """
        Load an ED25519 private key from raw bytes

        Args:
            raw_bytes (bytes): The raw bytes of the key

        Returns:
            Ed25519PrivateKey: Instance of Ed25519PrivateKey
        """
        return cls.from_class(
            _ED25519.Ed25519PrivateKey.from_private_bytes(data=raw_bytes)
        )

    @classmethod
    def generate(cls) -> "Ed25519PrivateKey":
        """
        Generates a new ED25519 Private Key

        Returns:
            Ed25519PrivateKey: Instance of Ed25519PrivateKey
        """
        return cls.from_class(_ED25519.Ed25519PrivateKey.generate())

    def raw_bytes(self) -> bytes:
        """
        Export the raw key bytes

        Returns:
            bytes: The key bytes
        """
        return self.key.private_bytes(
            encoding=_SERIALIZATION.Encoding.Raw,
            format=_SERIALIZATION.PrivateFormat.Raw,
            encryption_algorithm=_SERIALIZATION.NoEncryption(),
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
