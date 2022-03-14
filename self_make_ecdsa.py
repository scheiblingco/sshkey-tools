# pylint: disable-all
# Generate an ECDSA SSH Certificate according to:
# https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD

import os
import math
import random
from time import time
from base64 import b64encode, b64decode
from struct import pack
from paramiko.message import Message
from paramiko.ecdsakey import ECDSAKey
from paramiko.util import deflate_long

def encodeBytes(string):
    return pack('>I', len(string)) + string

def encodeString(string):
    return pack('>I', len(string)) + string.encode()

def encodeList(list, separator=False):
    encoded = b''
    for item in list:
        encoded = encoded + encodeString(item)
        if separator or separator == '':
            encoded = encoded + encodeString(separator)
    return encodeBytes(encoded)

def encodeUint64(num):
    return pack('>Q', num)


def encodeUint32(num):
    return pack('>I', num)

# def encodeMpint(num):
#     return pack('>I', len(str(num))) + str(num).encode()

def long_to_bytes(l_val):  
    b_len = math.ceil(math.log(l_val)/math.log(256))
    return int.to_bytes(l_val, b_len, 'big')

# def encodeMpint(num):
    # leng, byt = long_to_bytes(num)
    # return pack('>I', leng) + byt

def encodeMpint(num):
    return encodeBytes(deflate_long(num))
    # return encodeBytes(long_to_bytes(num))
    # from long_to_bytes import long_to_bytes
    # return encodeBytes(long_to_bytes(num))
    # from cryptography.utils import int_to_bytes
    # return encodeBytes(int_to_bytes(num))
    # return deflate_long(num)

# def encodeMpint2(num):
    # num_bytes = long_to_bytes(num)+1
    
    
def encodeSignature(r, s):
    return encodeMpint(r) + encodeMpint(s)
    

# Create a new bytes object
# Compare with paramikop
certificate = b''
certificate2 = Message()

# Add type
certificate += encodeString('ecdsa-sha2-nistp256-cert-v01@openssh.com')
certificate2.add_string('ecdsa-sha2-nistp256-cert-v01@openssh.com')

print(certificate == certificate2.asbytes())


# Add nonce
nonce = str(random.randint(2**10, 2**32))
certificate = certificate + encodeString(nonce)
certificate2.add_string(nonce)

# Add curve
certificate += encodeString('nistp256')
certificate2.add_string('nistp256')

print(certificate == certificate2.asbytes())

# Add user pubkey
with open('testcerts/ecdsa_user.pub', 'r') as f:
    user_key = f.read().split(' ')[1]
    user_key = Message(b64decode(user_key))
    _ = user_key.get_string()
    _ = user_key.get_string()
    user_key = user_key.get_string()

certificate += encodeBytes(user_key)
certificate2.add_string(user_key)

print(certificate == certificate2.asbytes())

# Add the serial number (numeric)
certificate += encodeUint64(123456)
certificate2.add_int64(123456)

print(certificate == certificate2.asbytes())

# Add the certificate type (1=User, 2=Host)
certificate += encodeUint32(1)
certificate2.add_int(1)

print(certificate == certificate2.asbytes())


# Add the key ID (alphanumeric, e.g. identifier)
certificate += encodeString('abcdefgh')
certificate2.add_string('abcdefgh')

print(certificate == certificate2.asbytes())


# Add the valid principals for the certificate (custom list)
principal_list = Message()
principal_list.add_string('root')
principal_list.add_string('regular_user')
principal_list.add_string('irregular_user')

certificate += encodeList(['root', 'regular_user', 'irregular_user'])
certificate2.add_string(principal_list.asbytes())

print(certificate == certificate2.asbytes())

# Add the valid after timestamp (now)
certificate += encodeUint64(int(time()))
certificate2.add_int64(int(time()))

# Add the valid before timestamp (12 hours)
certificate += encodeUint64(int(time() + (3600 * 12) ))
certificate2.add_int64(int(time() + (3600 * 12) ))



# Add critical options (empty list)
certificate += encodeString('')
certificate2.add_list([])

print(certificate == certificate2.asbytes())

# Add extensions (custom list formatting)
extension_list = Message()
extension_list.add_string('permit-X11-forwarding')
extension_list.add_string('')
extension_list.add_string('permit-agent-forwarding')
extension_list.add_string('')
extension_list.add_string('permit-port-forwarding')
extension_list.add_string('')
extension_list.add_string('permit-pty')
extension_list.add_string('')

certificate += encodeList(['permit-X11-forwarding', 'permit-agent-forwarding', 'permit-port-forwarding', 'permit-pty'], '')
certificate2.add_string(extension_list.asbytes())

print(certificate == certificate2.asbytes())


# # Add the the reserved part (currently unused by spec)
certificate += encodeString('')
certificate2.add_string('')

# Add the signature public key
# This is the full public key including identifier and curve
with open('testcerts/ecdsa_ca.pub', 'r') as f:
    ca_pubkey = f.read().split(' ')[1]
    ca_pubkey = b64decode(ca_pubkey)

certificate += encodeBytes(ca_pubkey)
certificate2.add_string(ca_pubkey)
print(certificate == certificate2.asbytes())


# Finally, add the signature
# Load the CA private key
ca_key2 = ECDSAKey.from_private_key_file('testcerts/ecdsa_ca')
# signature = ca_key2.sign_ssh_data(certificate)
# signature2 = ca_key2.sign_ssh_data(certificate2.asbytes())




# Import cryptography functionality
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

CURVES = {
    'secp256r1': hashes.SHA256,
    'secp384r1': hashes.SHA384,
    'secp521r1': hashes.SHA512
}


with open('testcerts/ecdsa_ca', 'rb') as f:
    ca = f.read()


ca_key = serialization.load_ssh_private_key(
    data=ca,
    password=None,
    backend=default_backend()
)

# curve = ec.ECDSA(CURVES[ca_key.curve.name]())
curve = ec.ECDSA(hashes.SHA256())

# Signature
sig = ca_key.sign(
    certificate2.asbytes(),
    curve
)

r, s = decode_dss_signature(sig)

# The paramiko way (1:1)
sigenc = Message()
sigenc.add_mpint(r)
sigenc.add_mpint(s)
print(sigenc.asbytes())

m = Message()
m.add_string('ecdsa-sha2-nistp256')
m.add_string(sigenc.asbytes())

certificate2.add_string(m.asbytes())

# print(m.asbytes())
# certificate2.add_string(m)
# certificate2.add_string(signature2)

# The self way
# print(encodeSignature(r, s))
# certificate += encodeBytes(m.asbytes())
sig2 = encodeSignature(r, s)
print(sig2)

# certificate += encodeString('ecdsa-sha2-nistp256') + sig2

print(sig2 == sigenc.asbytes())
# print(sig2)
# print(sigenc.asbytes())

sig3 = encodeString('ecdsa-sha2-nistp256') + encodeBytes(sig2)
# print(sig3)
# print(m.asbytes())
print(sig3 == m.asbytes())

certificate += encodeBytes(sig3)


# print(sig3 == m.asbytes())
# print(sig3)
# print(m.asbytes())

# certificate += encodeBytes(sig3)

# encodeBytes(
# # # print(encodeBytes(
#     encodeString('ecdsa-sha2-nistp256') +
#     sig2
# )

# print(certificate2.asbytes() == certificate)


# signature = encodeSignature("ecdsa-sha2-nistp256", r, s)


# signature = encodeSignature("ecdsa-sha2-nistp256", r, s)

# # print(sig)
# # print(encodeSignature(r, s))
# print(signature2.asbytes())
# print(signature)
# # print(encodeMpint(r))
# # print(encodeMpint2(r))
# # tst = Message()
# # tst.add_mpint(r)
# # print(tst.asbytes())


# import sys
# sys.exit()

# Sign the current certificate data
# signature = ca_key.sign_ssh_data(certificate)

# # Add the signature to the bottom of the certificate
# certificate += encodeBytes(signature)
# certificate2.add_bytes(signature)

# print(certificate == certificate2.asbytes())

# print(certificate)
# print(certificate2.asbytes())

# Write to file
with open('selfdone_cert', 'wb') as f:
    f.write(
        b'ecdsa-sha2-nistp256-cert-v01@openssh.com ' +
        b64encode(certificate) +
        b' User@Host'
    )

with open('paramiko_cert', 'wb') as f:
    f.write(
        b'ecdsa-sha2-nistp256-cert-v01@openssh.com ' +
        b64encode(certificate2.asbytes()) +
        b' User@Host'
    )

# Finally, verify the certificate has been correctly created
os.system('ssh-keygen -Lf selfdone_cert')
os.system('ssh-keygen -Lf paramiko_cert')
