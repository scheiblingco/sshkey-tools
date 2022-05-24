from src.sshkey_tools.fields import CERT_TYPE, RSA_ALGS
import src.sshkey_tools.cert as _CERT
import src.sshkey_tools.keys as _KEYS
from datetime import datetime, timedelta
import os

rsa_ca = _KEYS.RSAPrivateKey.generate(1024)
dsa_ca = _KEYS.DSAPrivateKey.generate(1024)
ecdsa_ca = _KEYS.ECDSAPrivateKey.generate(_KEYS.ECDSA_CURVES.P256)
ed25519_ca = _KEYS.ED25519PrivateKey.generate()

rsa_user = _KEYS.RSAPrivateKey.generate(1024).public_key
dsa_user = _KEYS.DSAPrivateKey.generate(1024).public_key
ecdsa_user = _KEYS.ECDSAPrivateKey.generate(_KEYS.ECDSA_CURVES.P384).public_key
ed25519_user = _KEYS.ED25519PrivateKey.generate().public_key


now = datetime.now()
then = datetime.now() + timedelta(hours=12)

cert_details = {
    'serial': 1234567890,
    'cert_type': CERT_TYPE.USER,
    'key_id': 'KeyIdentifier',
    'principals': [
        'Good',
        'Morning',
        'Starshine'
    ],
    'valid_after': now,
    'valid_before': then,
    'critical_options': [],
    'extensions': [
        'permit-agent-forwarding'
    ]
}

pubkeys = [
    {
        'file': rsa_user,
        'type': _CERT.RSACertificate
    },
    {
        'file': dsa_user,
        'type': _CERT.DSACertificate
    },
    {
        'file': ecdsa_user,
        'type': _CERT.ECDSACertificate
    },
    {
        'file': ed25519_user,
        'type': _CERT.ED25519Certificate
    }
]

privkeys = [
    rsa_ca,
    dsa_ca,
    ecdsa_ca,
    ed25519_ca
]

for item in pubkeys:
    for ca in privkeys:
        cert = item['type'](
            item['file'],
            ca,
            **cert_details
        )
        cert.sign()
        cert.to_file('testcert')
        os.system('ssh-keygen -Lf testcert')


# cert = ED25519Certificate(ed25519_pub, ed25519_priv,
#     serial=123456,
#     cert_type=CERT_TYPE.USER,
#     key_id='mfdutra',
#     principals=[
#         'hello',
#         'world'
#     ],
#     valid_after=now,
#     valid_before=then,
#     critical_options=[],
#     extensions=['permit-agent-forwarding'],
# )


# cert.sign()
# print(cert.to_bytes())
# open('testcert', 'wb').write(cert.to_string())
# os.system('ssh-keygen -Lf testcert')

# privkey_pub = cert.
# print(privkey_pub)
# from time import time as timestamp
# from base64 import b64encode, b64decode
# import tstut as utils

# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
# with open('ecdsa_user.pub', 'r') as f:
#         file_content = f.read().split(' ')

#         # Get the two major parts from the file
#         # The certificate data
#         data = b64decode(file_content[1])
        
#         # And the comment at the end of the file (e.g. User@Host)
#         user_comment = file_content[2]

#         # Convert the user public key to its parts
#         # The Key type (e.g. ecdsa-sha2-nistp256)
#         user_keytype, data = utils.decode_string(data)
        
#         # The curve (e.g. nistp256)
#         user_keycurve, data = utils.decode_string(data)
        
#         # The public key in bytes
#         user_pubkey, data = utils.decode_string(data) 

# print(utils.encode_string(user_keycurve) + utils.encode_string(user_pubkey))
