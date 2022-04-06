from src.sshkey_tools.crypto import PublicKey, RSAPublicKey, ECDSAPublicKey, DSAPublicKey, ED25519PublicKey
from src.sshkey_tools.crypto import PrivateKey
# from src.sshkey_tools.crypto import PublicKeyBytes as PKBytes
from cryptography.hazmat.primitives import serialization
from src.sshkey_tools import utils
from src.sshkey_tools import certificates as cert
from src.sshkey_tools.certificates import Certificate, CertificateTypes
from base64 import b64decode



test = PublicKey.from_file('test_keys/rsa_key.pub')
test2 = PublicKey.from_file('test_keys/ecdsa_key.pub')
test3 = PublicKey.from_file('test_keys/ed25519_key.pub')
test4 = PublicKey.from_file('test_keys/dss_key.pub')

print("Done")



testp = PrivateKey.from_file('test_keys/rsa_key')
testp2 = PrivateKey.from_file('test_keys/ecdsa_key')
testp3 = PrivateKey.from_file('test_keys/ed25519_key')
test4 = PrivateKey.from_file('test_keys/dss_key')

print("Done")




# with open('test_keys/rsa_key.pub', 'rb') as f:
#     split = f.read().split(b' ')
#     print(split[0])
#     data = b64decode(split[1])
#     str1, data = utils.decode_string(data)
#     nums, data = utils.decode_mpint(data)
#     nums2, data = utils.decode_mpint(data)
    


# rsa_pubkey = PublicKey.from_file('test_keys/rsa_key.pub')
# rsa_privkey = PrivateKey.from_file('test_keys/rsa_key')


# numbers = rsa_pubkey.key_object.public_numbers()
# rsa_from_numbers = RSAPublicKey.from_public_numbers(numbers.e, numbers.n)



print("Done")






# pubk = PublicKey.from_file('test_ecdsa.pub')
# certificate = cert.Certificate(pubk, CertificateTypes.USER, 64)

# print(pubk.key_type())
# print(pubk.key_curve())
# print("test")


# rsa_pubkey = PublicKey.from_file('test_rsa.pub')
# dsa_pubkey = PublicKey.from_file('test_dsa.pub')
# ecdsa_pubkey = PublicKey.from_file('test_ecdsa.pub')
# ed25519_pubkey = PublicKey.from_file('test_ed25519.pub')

# rsa_privkey = PrivateKey.from_file('test_rsa')
# dsa_privkey = PrivateKey.from_file('test_dsa')
# ecdsa_privkey = PrivateKey.from_file('test_ecdsa')
# ed25519_privkey = PrivateKey.from_file('test_ed25519')

# print("Done")

# from dataclasses import dataclass
# @dataclass
# class Dict:
#     something: int = 1
#     somethingelse: str = "1"

# class TestAttr:
#     test: Dict = Dict
        
#     def __setattr__(self, attr, value):
#         self.test.__dict__[attr] = value
        
#     def __getattr__(self, attr):
#         return self.test.__dict__[attr]

# cl = TestAttr()
# print(cl.something)

# cl.something = 2
# print(cl.something)