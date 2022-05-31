"""
Exceptions thrown by sshkey_tools
"""


class InvalidKeyException(ValueError):
    """
    Raised when a key is invalid.
    """


class InvalidFieldDataException(ValueError):
    """
    Raised when a field contains invalid data
    """


class InvalidCurveException(ValueError):
    """
    Raised when the ECDSA curve
    is not supported.
    """


class InvalidHashException(ValueError):
    """
    Raised when the hash type is
    not available
    """


class InvalidDataException(ValueError):
    """
    Raised when the data passed
    to a function is invalid
    """


class InvalidCertificateFieldException(KeyError):
    """
    Raised when the certificate field is not found/not editable
    """


class InsecureNonceException(ValueError):
    """
    Raised when the nonce is too short to be secure.
    Especially important for ECDSA, see:
    https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a
    """


class IntegerOverflowException(ValueError):
    """
    Raised when the integer is too large to be represented
    """


class SignatureNotPossibleException(ValueError):
    """
    Raised when the signature of a certificate is not possible,
    usually because no private key has been loaded or a required
    field is empty.
    """


class NotSignedException(ValueError):
    """
    Raised when trying to export a certificate that has not been
    signed by a private key
    """


class InvalidCertificateFormatException(ValueError):
    """
    Raised when the format of the certificate is invalid
    """


class InvalidKeyFormatException(ValueError):
    """
    Raised when the format of the chosen key is invalid,
    normally when trying to use a private key instead of
    a public key or vice versa
    """


class NoPrivateKeyException(ValueError):
    """
    Raised when no private key is present to sign with
    """


class SSHCertificateException(ValueError):
    """
    Raised when the SSH Certificate is invalid
    """


class InvalidSignatureException(ValueError):
    """
    Raised when the signature checked is invalid
    """


class InvalidClassCallException(ValueError):
    """
    Raised when trying to instantiate a parent class
    """
