
from src.sshkey_tools.keys import PrivateKey, PublicKey
from cryptography.hazmat.primitives.asymmetric import (
    rsa as _RSA,
    dsa as _DSA,
    ec as _ECDSA,
    ed25519 as _ED25519
)
from src.sshkey_tools.cert import RSACertificateClass
from src.sshkey_tools import fields as _FIELDS
from struct import pack, unpack

rsa_priv = PrivateKey.from_file('rsa', None)
dsa_priv = PrivateKey.from_file('dsa', None)
ecdsa_priv = PrivateKey.from_file('ecdsa', None)
ed25519_priv = PrivateKey.from_file('ed25519', None)

rsa_pub = PublicKey.from_file('rsa.pub')
dsa_pub = PublicKey.from_file('dsa.pub')
ecdsa_pub = PublicKey.from_file('ecdsa.pub')
ed25519_pub = PublicKey.from_file('ed25519.pub')


test = _FIELDS.ED25519PubkeyField.encode(ed25519_pub)
test2 = _FIELDS.ED25519PubkeyField.decode(test)


# from cryptography.hazmat.primitives import serialization





# strang = ed25519_pub.to_string()
# strang2 = ed25519_pub.key.public_bytes(
#     encoding=serialization.Encoding.Raw,
#     format=serialization.PublicFormat.Raw
# )


# test = _FIELDS.ECDSAPubkeyField.encode(ecdsa_pub)
# test2 = _FIELDS.ECDSAPubkeyField.decode(test)




# from base64 import b64decode
# file_content = b64decode(open('ecdsa.pub').read().split(' ')[1])
# _, data = _FIELDS.StringField.decode(file_content)

# cert_bytes = b64decode(ecdsa_pub.to_bytes().split(b' ')[1])
# _, cert_bytes = _FIELDS.StringField.decode(cert_bytes)
        
# assert data == cert_bytes


print("Hold")    


# test = RSACertificateClass(
#     rsa_pub, 
#     rsa_priv, 
#     pubkey_type = "ssh-rsa-cert-v01@openssh.com",
#     nonce="abcdefg"
# )


