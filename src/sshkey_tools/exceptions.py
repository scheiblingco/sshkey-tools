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