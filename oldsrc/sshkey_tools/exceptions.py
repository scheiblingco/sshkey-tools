class FileAccessException(Exception):
    """Exception for when file access fails"""
    pass

class PasswordNeededException(Exception):
    """Exception for when a password is needed to unlock the private key"""
    pass