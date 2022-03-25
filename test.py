# # pylint: disable-all
from src.sshkey_tools.utils import *
from base64 import b64decode, b64encode
from time import time
from cryptography.hazmat.backends import default_backend
import src.sshkey_tools.fields as fields


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric import padding

# Create an RSA Certificate
with open('test_rsa_user.pub', 'rb') as f:
    user_pubkey = f.read()
    
with open('test_rsa_ca.pub', 'r') as f:
    ca_public_key = public_key_to_dict(f.read())
    
with open('test_rsa_ca', 'rb') as f:
    ca_private_key = private_key_to_object(f.read())

   
    
cert = b''
cert += fields.StringField('rsa-sha2-512-cert-v01@openssh.com').to_bytes()
cert += fields.NonceField(64).to_bytes()
cert += fields.RSAUserPubkeyField(user_pubkey).to_bytes()
cert += fields.Integer64Field(123456).to_bytes()
cert += fields.CertificateTypeField(fields.CertificateType.USER).to_bytes()
cert += fields.StringField('abcdefgh').to_bytes()
cert += fields.ListField(['root', 'otheruser']).to_bytes()
cert += bytes(fields.TimeField())
cert += bytes(fields.TimeField(3600*12))
cert += fields.ListField([], True).to_bytes()
cert += fields.ListField(['permit-X11-forwarding'], True).to_bytes()
cert += fields.StringField('').to_bytes()
cert += fields.StringField(ca_public_key['key']).to_bytes()

cert += fields.RSASignatureField(rsa_sign_bytes(
    data=cert,
    private_key=ca_private_key
)).to_bytes()

with open('test_rsa_user-cert2.pub', 'w') as f:
    f.write(
        get_certificate_file(
            type='rsa-sha2-512-cert-v01@openssh.com',
            data=cert,
            comment='User@Host'
        )
    )
import os
os.system('ssh-keygen -Lf test_rsa_user-cert2.pub')


# cert += encode_string('rsa-sha2-512-cert-v01@openssh.com')
# cert += encode_string(generate_secure_nonce(32))
# cert += encode_mpint(user_pubkey["key"].public_numbers().e)
# cert += encode_mpint(user_pubkey["key"].public_numbers().n)
# cert += encode_int64(1234567890)
# cert += encode_int(1)
# cert += encode_string('abcdefgh')
# cert += encode_list(['root', 'useracc'])
# cert += encode_int64(int(time()))
# cert += encode_int64(int(time() + (3600*12)))
# cert += encode_list([], True)
# cert += encode_list(['permit-X11-forwarding'], True)
# cert += encode_string('')
# cert += encode_string(ca_public_key['key'])

# cert += encode_rsa_signature(
#     rsa_sign_bytes(
#         data=cert,
#         private_key=ca_private_key
#     ),
#     "rsa-sha2-512"
# )

# with open('test_rsa_user-cert.pub', 'w') as f:
#     f.write(get_certificate_file(
#         type='rsa-sha2-512-cert-v01@openssh.com',
#         data=cert,
#         comment=user_pubkey["comment"]
#     ))
    
# import os
# os.system('ssh-keygen -Lf test_rsa_user-cert.pub')