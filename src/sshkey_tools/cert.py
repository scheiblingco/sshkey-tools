from .keys import (
    PublicKey,
    PrivateKey,
    RSAPublicKey,
    RSAPrivateKey
)
from . import fields as _FIELD
from . import exceptions as _EX

CERTIFICATE_FIELDS = {
    "pubkey_type": _FIELD.PubkeyTypeField,
    "nonce": _FIELD.NonceField
}


class SSHCertificate:
    def __init__(
        self,
        *args,
        **kwargs
    ):
        pass
    

class RSACertificateClass(SSHCertificate):
    def __init__(
        self, 
        public_key: RSAPublicKey,
        private_key: PrivateKey,
        **kwargs
    ):
        self.public_key = public_key
        self.private_key = private_key
        
        self.fields = dict(CERTIFICATE_FIELDS)
        
        for item in kwargs.keys():
            if not isinstance(
                self.fields.get(item, None)(kwargs[item]),
                _FIELD.CertificateField
            ):
                raise _EX.InvalidCertificateFieldException(
                    "The specified certificate field is invalid"
                )
            
            self.fields[item] = self.fields[item](kwargs[item])
                
            
        print("Hold")
