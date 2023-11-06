from src.sshkey_tools import (
    fields as _F,
    keys as _K,
    exceptions as _E,
    signatures as _S
)
from base64 import b64decode
with open("hello.txt.sig", 'rb') as f:
    fx = f.read()

data = b''.join(fx.split(b'\n')[1:-2])
data = b64decode(data)

# # Get preamble
# preamble, data = data[0:6], data[6:]

# # Get version
# version, data = _F.Integer32Field.decode(data)

# # Get public key
# pubkey, data = _F.BytestringField.decode(data)
# pubkey_type, pubkey = _F.BytestringField.decode(pubkey)

# # Get namespace
# namespace, data = _F.StringField.decode(data)

# # Get reserved
# reserved, data = _F.ReservedField.decode(data)

# # Get hash alg
# hash_alg, data = _F.BytestringField.decode(data)

# # Get signature
# signature, data = _F.SignatureField.from_decode(data)
# # sigtype, signature = _F.BytestringField.decode(signature)

sign = _S.SSHSignature.decode(data)



print()