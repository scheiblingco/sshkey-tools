from multiprocessing.sharedctypes import Value


class InvalidKeyException(ValueError):
    pass

class InvalidCurveException(ValueError):
    pass

class InvalidHashException(ValueError):
    pass

class InvalidDataException(ValueError):
    pass

class InvalidCertificateFieldException(KeyError):
    pass

class ShortNonceException(ValueError):
    pass

class IntegerOverflowException(ValueError):
    pass

class SignatureNotPossibleException(ValueError):
    pass

class NotSignedException(ValueError):
    pass

class InvalidCertificateFormatException(ValueError):
    pass

class InvalidKeyFormatException(ValueError):
    pass

class NoPrivateKeyException(ValueError):
    pass

class SSHCertificateException(ValueError):
    pass