from src.sshkey_tools.models import PublicKey, PrivateKey, CertificateAuthority, Certificate
from src.sshkey_tools.crypto import RSA, DSA, ECDSA, ED25519

from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend


with open('test_key', 'rb') as f:
    key_data = f.read()


key = crypto_serialization.load_pem_private_key(
            key_data,
            password='password',
            backend=crypto_default_backend()
        )

print(key)



# key = PrivateKey.generate(algorithm=ECDSA, bits=256)
# key.to_file('keyfile_test')
# print(str(key.get_public_key()))

# key2 = PrivateKey.from_file('keyfile_test')
# print(str(key2))
# print(key2)
# print(key2.alg)

# key = PrivateKey.from_file('test_key', password='password'.encode('utf-8'))
# print(str(key))


# print(str(key))
# print(str(key.get_public_key()))

# with open('test.key', 'w') as f:
#     f.write(str(key))
    
# with open('test.crt', 'w') as f:
#     f.write(str(key.get_public_key()))


# @classmethod for extra constructors

# https://gist.github.com/thomdixon/bc3d664b6305adec9ecbc155b5ca3b6d
# https://stackoverflow.com/questions/59243185/generating-elliptic-curve-private-key-in-python-with-the-cryptography-library
# https://dev.to/aaronktberry/generating-encrypted-key-pairs-in-python-69b
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/