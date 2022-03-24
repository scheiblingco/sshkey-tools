# pylint: disable-all
from src.sshkey_tools.utils import *
from base64 import b64decode, b64encode
from time import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

CURVES = {
    'secp256r1': hashes.SHA256,
    'secp384r1': hashes.SHA384,
    'secp521r1': hashes.SHA512
}

with open('test_ecdsa_user.pub', 'r') as f:
    file_content = f.read().split(' ')
    
    data = b64decode(file_content[1])
    user_comment = file_content[2]
    user_keytype, data = decode_string(data)
    user_keycurve, data = decode_string(data)
    user_pubkey, data = decode_string(data)
    
with open('test_ecdsa_ca.pub', 'r') as f:
    ca_pubkey = b64decode(f.read().split(' ')[1])
    
with open('test_ecdsa_ca', 'rb') as f:
    ca_privkey = f.read()
    
print(user_pubkey)
print(ca_pubkey)
certificate = b''
certificate += encode_string(f'ecdsa-sha2-nistp256-cert-v01@openssh.com')
certificate += encode_string(generate_secure_nonce(64))
certificate += encode_string(user_keycurve)
certificate += encode_string(user_pubkey)
certificate += encode_int64(12345)
certificate += encode_int(1)
certificate += encode_string('abcdefgh')
certificate += encode_int64(int(time()))
certificate += encode_int64(int(time() + 3600))
certificate += encode_list([], True)
certificate += encode_list(['permit-agent-forwarding'], True)
certificate += encode_string('')
certificate += encode_string(ca_pubkey)

signer = serialization.load_ssh_private_key(
    data=ca_privkey,
    password=None
)

# curve = ec.ECDSA(CURVES[signer.curve.name]())
curve = ec.ECDSA(hashes.SHA256())

print(curve)
signature = signer.sign(
    certificate,
    curve
)

r, s = decode_dss_signature(signature)

certificate += encode_ecdsa_signature(r, s, f'ecdsa-sha2-nistp256')

with open('test_ecdsa_user-cert.pub', 'wb') as f:
    f.write(
        b'ecdsa-sha2-nistp256-cert-v01@openssh.com %b %s' % (
            user_keytype,
            b64encode(certificate),
            user_comment.encode()
        )
    )
    
import os
os.system('ssh-keygen -Lf test_ecdsa_user-cert.pub')