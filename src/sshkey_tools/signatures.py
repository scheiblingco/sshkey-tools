# Format:

# byte[6]   MAGIC_PREAMBLE (SSHSIG)
# uint32    SIG_VERSION (0x01)
# string    publickey
# string    namespace
# string    reserved
# string    hash_algorithm
# string    signature

from .cert import Fieldset, dataclass, Union
from . import (
    fields as _FIELD,
    keys as _KEY,
    exceptions as _EX
)

@dataclass
class SignatureFieldset(Fieldset):
    """Fields for SSH Signature"""
    
    DECODE_ORDER = [
        "magic_preamble",
        "sig_version",
        "public_key",
        "namespace",
        "reserved",
        "hash_algorithm",
        "signature"
    ]
    
    magic_preamble: _FIELD.SshsigField = _FIELD.SshsigField.factory
    sig_version: _FIELD.SignatureVersionField = _FIELD.SignatureVersionField.factory
    public_key: _FIELD.PublicKeyField = _FIELD.PublicKeyField.factory
    
    namespace: _FIELD.StringField = _FIELD.StringField.factory  
    reserved: _FIELD.ReservedField = _FIELD.ReservedField.factory
    hash_algorithm: _FIELD.SignatureHashAlgorithmField = _FIELD.SignatureHashAlgorithmField.factory
    signature: _FIELD.SignatureField = _FIELD.SignatureField.factory

class SSHSignature:
    """
    General class for SSH Signatures, used for loading and parsing.
    """
    def __init__(
        self, signer_privkey: _KEY.PrivateKey = None,
        fields: SignatureFieldset = SignatureFieldset
    ):
        self.fields = fields() if isinstance(fields, type) else fields
        
        if isinstance(signer_privkey, type) and signer_privkey is not None:
            self.fields.replace_field(
                "signature", _FIELD.SignatureField.from_object(signer_privkey)
            )        
    
    @classmethod
    def decode(cls, data: bytes) -> "SSHSignature":
        """
        Loads an existing SSH Signature from byte contents

        Args:
            data (bytes): The normalized byte data from the .sig-file

        Returns:
            SSHSignature: The parsed SSH Signature
        """
        sig_fields, data = SignatureFieldset.decode(data)
        return cls(fields=sig_fields)