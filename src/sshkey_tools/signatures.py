# Format:

# byte[6]   MAGIC_PREAMBLE (SSHSIG)
# uint32    SIG_VERSION (0x01)
# string    publickey
# string    namespace
# string    reserved
# string    hash_algorithm
# string    signature
from base64 import b64decode
from .cert import Fieldset, dataclass, Union
from prettytable import PrettyTable
from .utils import concat_to_bytestring, concat_to_string, ensure_bytestring
from . import (
    fields as _FIELD,
    keys as _KEY,
    exceptions as _EX,
    utils as _U
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
    
    namespace: _FIELD.SignatureNamespaceField = _FIELD.StringField.factory  
    reserved: _FIELD.ReservedField = _FIELD.ReservedField.factory
    hash_algorithm: _FIELD.SignatureHashAlgorithmField = _FIELD.SignatureHashAlgorithmField.factory
    signature: _FIELD.SignatureField = _FIELD.SignatureField.factory

    def __bytes__(self):
        return concat_to_bytestring(
            bytes(self.magic_preamble),
            bytes(self.namespace),
            bytes(self.reserved),
            bytes(self.hash_algorithm)
        )

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
    def from_file(cls, path: str, encoding: str = 'none') -> "SSHSignature":
        """
        Loads an existing SSH Signature from a file

        Args:
            path (str): The path to the file
            encoding (str, optional): The encoding of the file. None will load the byte content directly. Defaults to 'utf-8'.

        Returns:
            SSHSignature: SSH Signature Object
        """
        with open(path, 'rb' if encoding == 'none' else 'r') as f:
            data = f.read()

        return cls.from_string(data, encoding if encoding != 'none' else None)
    
    @classmethod
    def from_string(cls, data: Union[str, bytes], encoding: str = 'utf-8') -> "SSHSignature":
        """
        Loads an existing SSH Signature from file contents/string

        Args:
            data (str): The normalized string data from the .sig-file

        Returns:
            SSHSignature: The parsed SSH Signature
        """
        if isinstance(data, str):
            data = data.encode(encoding)
        
        if b'BEGIN SSH SIGNATURE' in data:
            data = data.replace(b'-----BEGIN SSH SIGNATURE-----\n', b'')
        
        if b'END SSH SIGNATURE' in data:
            data = data.replace(b'-----END SSH SIGNATURE-----', b'')
        
        data = data.strip(b"\n \t")
        
        return cls.decode(b64decode(data))
    
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
    
    def get_signable(self, data: Union[str, bytes]) -> bytes:
        """
        Returns the signable data for the signature or verification

        Returns:
            bytes: The signable data
        """
        hash = b""
        if self.fields.hash_algorithm.value == "sha256":
            hash = _U.sha256_hash(ensure_bytestring(data))
        elif self.fields.hash_algorithm.value == "sha512":
            hash = _U.sha512_hash(ensure_bytestring(data))
        else:
            raise _EX.InvalidHashAlgorithmException(
                f"Unknown hash algorithm {self.fields.hash_algorithm}"
            )
        
        return bytes(self.fields) + _FIELD.StringField.encode(hash)

    def __str__(self) -> str:
        table = PrettyTable(["Field", "Value"])

        for item in (self.header, self.fields, self.footer):
            for row in item.__table__():
                table.add_row(row)

        return str(table)

    def get(self, field: str):
        if field in self.fields.getattrs():
            return self.fields.get(field, None)

        raise _EX.InvalidCertificateFieldException(f"Unknown field {field}")

    def set(self, field: str, data):
        if field in self.fields.getattrs():
            self.fields.set(field, data)
        
        raise _EX.InvalidCertificateFieldException(f"Unknown field {field}")
    
    def verify(
        self, data, public_key: _KEY.PublicKey = None, raise_on_error: bool = False
    ) -> bool:
        if not public_key:
            public_key = self.get('public_key').value
            
        public_key.verify(
            self.get_signable(data),
            self.fields.signature.value
        ) 
            
            
            
        print()
        