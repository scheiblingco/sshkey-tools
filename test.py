from src.sshkey_tools.cryptography import PublicKey, RSAPublicKey, ECDSAPublicKey, DSAPublicKey, ED25519PublicKey
from src.sshkey_tools.cryptography import PrivateKey
from src.sshkey_tools.cryptography import PublicKeyBytes as PKBytes
from cryptography.hazmat.primitives import serialization
from src.sshkey_tools import utils
from base64 import b64decode

rsa_pubkey = PublicKey.from_file('test_rsa.pub')
dsa_pubkey = PublicKey.from_file('test_dsa.pub')
ecdsa_pubkey = PublicKey.from_file('test_ecdsa.pub')
ed25519_pubkey = PublicKey.from_file('test_ed25519.pub')

rsa_privkey = PrivateKey.from_file('test_rsa')
dsa_privkey = PrivateKey.from_file('test_dsa')
ecdsa_privkey = PrivateKey.from_file('test_ecdsa')
ed25519_privkey = PrivateKey.from_file('test_ed25519')

print("Done")