# from src.sshkey_tools.models import PublicKey, PrivateKey, CertificateAuthority, Certificate
# from src.sshkey_tools.crypto import RSA, DSA, ECDSA, ED25519







# test = PrivateKey.from_file('test_key', 'password')
# test = PrivateKey.from_file('test_key_ecdsa', 'password2')
# test = PrivateKey.from_file('test_key_dsa', 'password3')
# test = PrivateKey.from_file('test_key_ed', 'password3')
# test = PrivateKey.from_file('test_key_nopass')


# with open('test_key', 'rb') as f:
#     key_data = f.read()


# key = crypto_serialization.load_pem_private_key(
#             key_data,
#             password='password'.encode(),
#             backend=crypto_default_backend()
#         )

# print(key)

# with open('test_key_ed', 'rb') as f:
#     key = f.read()
    
# keydata = crypto_serialization.load_ssh_private_key(
#     key,
#     password='password3'.encode(),
#     backend=crypto_default_backend()
# )

# print(keydata)

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


#!/usr/bin/env python2
#
# OpenSSH certificate decoder in Python
#
# References:
# - https://tools.ietf.org/html/rfc4251.html#section-5
# - http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#
# Copyright (c) 2016 Julian Kornberger <jk+github@digineo.de>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# import base64, json
# from struct import unpack

# def Decode(base64encoded):
#   certType, bin = decodeString(base64.b64decode(base64encoded))

#   h = {}
#   for typ, key in formats[certType]:
#     val, bin = typ(bin)
#     h[key] = str(val)
#   return h


# def decodeUint32(value):
#   return unpack('>I', value[:4])[0], value[4:]

# def decodeUint64(value):
#   return unpack('>Q', value[:8])[0], value[8:]

# def decodeMpint(value):
#   size = unpack('>I', value[:4])[0]+4
#   return None, value[size:]

# def decodeString(value):
#   size = unpack('>I', value[:4])[0]+4
#   return value[4:size], value[size:]

# def decodeList(value):
#   joined, remaining = decodeString(value)
#   list = []
#   while len(joined) > 0:
#     elem, joined = decodeString(joined)
#     list.append(elem)
#   return list, remaining

# rsaFormat = [
#   (decodeString, "nonce"),
#   (decodeMpint,  "e"),
#   (decodeMpint,  "n"),
#   (decodeUint64, "serial"),
#   (decodeUint32, "type"),
#   (decodeString, "key id"),
#   (decodeString, "valid principals"),
#   (decodeUint64, "valid after"),
#   (decodeUint64, "valid before"),
#   (decodeString, "critical options"),
#   (decodeString, "extensions"),
#   (decodeString, "reserved"),
#   (decodeString, "signature key"),
#   (decodeString, "signature"),
# ]

# dsaFormat = [
#   (decodeString, ),
#   (decodeString, "nonce"),
#   (decodeMpint,  "p"),
#   (decodeMpint,  "q"),
#   (decodeMpint,  "g"),
#   (decodeMpint,  "y"),
#   (decodeUint64, "serial"),
#   (decodeUint32, "type"),
#   (decodeString, "key id"),
#   (decodeString, "valid principals"),
#   (decodeUint64, "valid after"),
#   (decodeUint64, "valid before"),
#   (decodeString, "critical options"),
#   (decodeString, "extensions"),
#   (decodeString, "reserved"),
#   (decodeString, "signature key"),
#   (decodeString, "signature"),
# ]

# ecdsaFormat = [
#   (decodeString, "nonce"),
#   (decodeString, "curve"),
#   (decodeString, "public_key"),
#   (decodeUint64, "serial"),
#   (decodeUint32, "type"),
#   (decodeString, "key id"),
#   (decodeString, "valid principals"),
#   (decodeUint64, "valid after"),
#   (decodeUint64, "valid before"),
#   (decodeString, "critical options"),
#   (decodeString, "extensions"),
#   (decodeString, "reserved"),
#   (decodeString, "signature key"),
#   (decodeString, "signature"),
# ]

# ed25519Format = [
#   (decodeString, "nonce"),
#   (decodeString, "pk"),
#   (decodeUint64, "serial"),
#   (decodeUint32, "type"),
#   (decodeString, "key id"),
#   (decodeList,   "valid principals"),
#   (decodeUint64, "valid after"),
#   (decodeUint64, "valid before"),
#   (decodeString, "critical options"),
#   (decodeString, "extensions"),
#   (decodeString, "reserved"),
#   (decodeString, "signature key"),
#   (decodeString, "signature"),
# ]

# formats = {
#   "ssh-rsa-cert-v01@openssh.com":        rsaFormat,
#   "ssh-dss-cert-v01@openssh.com":        dsaFormat,
#   "ecdsa-sha2-nistp256-v01@openssh.com": ecdsaFormat,
#   b"ecdsa-sha2-nistp256-cert-v01@openssh.com": ecdsaFormat,
#   "ecdsa-sha2-nistp384-v01@openssh.com": ecdsaFormat,
#   "ecdsa-sha2-nistp521-v01@openssh.com": ecdsaFormat,
#   "ssh-ed25519-cert-v01@openssh.com":    ed25519Format,
# }

# if __name__ == "__main__":
#   import sys
#   if len(sys.argv) > 1:
#     with open(sys.argv[1],'r') as f:
#       res = Decode(f.read().split(" ")[1])
#       print(json.dumps(res, indent=2))

#   else:
#     print("Usage: %s [path to certificate]" % sys.argv[0])
#     exit(1)




# import base64
# from struct import pack, unpack
# from cryptography.hazmat.primitives import serialization as crypto_serialization
# from cryptography.hazmat.primitives import hashes as crypto_hashes
# from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
# from cryptography.hazmat.backends import default_backend as crypto_default_backend


# stsz = lambda x: unpack('>I', x[:4])[0]+4
# def decodeList(val):
#     while len(val) > 0:
#         elem, val = val[4:stsz(val)], val[stsz(val):]
#         yield elem

# def st_to_lst(x):
#     res = []
#     while len(x) > 0:
#         rp, x = x[4:stsz(bin)], x[stsz(bin):]
#         res.append(rp)
#     return res


# with open('ssh_ca', 'rb') as f:
#     ca_data = f.read()
    
# with open('ssh_user.pub', 'r') as f:
#     pub_data = f.read()
    
# with open('ssh_user-cert.pub', 'r') as f:
#     cert = f.read()


# pub_parts = pub_data.split(' ')

# cert_parts = cert.split(' ')
# result = {}


# bin = base64.b64decode(pub_parts[1])

# _, bin = bin[4:stsz(bin)], bin[stsz(bin):]
# # print(result)
# _, bin = bin[4:stsz(bin)], bin[stsz(bin):]
# # print(result)
# pubkey, bin = bin[4:stsz(bin)], bin[stsz(bin):]
# pubkey = base64.b64encode(pubkey)
# # print(base64.b64encode(result))


# bin = base64.b64decode(cert_parts[1])

# # Key type
# # e.g. eccdsa-sha2-nistp256-cert-v01@openssh.com
# result['keytype'], bin = bin[4:stsz(bin)], bin[stsz(bin):]

# # Nonce (randomchars)
# result['nonce'], bin = base64.b64encode(bin[4:stsz(bin)]), bin[stsz(bin):]

# # Curve
# # e.g. nistp256
# result['curve'], bin = bin[4: stsz(bin)], bin[stsz(bin):]

# # Public key data (no metadata)
# result['public_key'], bin = base64.b64encode(bin[4:stsz(bin)]), bin[stsz(bin):]

# # Serial
# # e.g. 123
# result['serial'], bin = unpack('>Q', bin[:8])[0], bin[8:]

# # Type
# # 1 = User
# # 2 = Host
# result['type'], bin = unpack('>I', bin[:4])[0], bin[4:]

# # Key Identifier
# # e.g. mfdutra
# result['key_id'], bin = bin[4:stsz(bin)], bin[stsz(bin):]

# # Valid principals
# result['principals'], bin = bin[4:stsz(bin)], bin[stsz(bin):]

# # Valid after
# result['valid_after'], bin = unpack('>Q', bin[:8])[0], bin[8:]

# # Valid before
# result['valid_before'], bin = unpack('>Q', bin[:8])[0], bin[8:]

# # Options (critical)
# result['critical_options'], bin = bin[4:stsz(bin)], bin[stsz(bin):]

# # Extensions
# result['extensions'], bin = bin[4:stsz(bin)], bin[stsz(bin):]

# # Reserved
# result['reserved'], bin = bin[4:stsz(bin)], bin[stsz(bin):]

# # Signer pubkey
# result['signer_pubkey'], bin = bin[4:stsz(bin)], bin[stsz(bin):]

# print(result)


# to_sign = pack('>I', )


# # Signature
# # result['signature'] = []
# # temp, bin = bin[4:stsz(bin)], bin[stsz(bin):]

# # temp2, temp = temp[4:stsz(temp)], temp[stsz(temp):]
# # result['signature'].append(temp2)
# # temp2, temp = temp[4:stsz(temp)], temp[stsz(temp):]
# # result['signature'].append(temp2)
# # result['signature'][2], temp = temp[4:stsz(temp)], temp[stsz(temp):]
# # print(len(bin))

# # print(result)


from paramiko.message import Message
from paramiko.ecdsakey import ECDSAKey
from base64 import b64encode, b64decode
from time import time

with open('testcerts/ecdsa_user-cert.pub', 'r') as f:
    cert = f.read().split(' ')[1]
    certmsg = Message(b64decode(cert))
    
pkey = ECDSAKey.from_private_key_file('testcerts/ecdsa_ca')


msgcopy = Message(certmsg.asbytes())

decoded = {
    'cert_type': msgcopy.get_string(),
    'nonce': msgcopy.get_string(),
    'curve': msgcopy.get_string(),
    'public_key': msgcopy.get_string(),
    'serial': msgcopy.get_int64(),
    'type': msgcopy.get_int(),
    'keyid': msgcopy.get_string(),
    'principals': msgcopy.get_string(),
    'valid_after': msgcopy.get_int64(),
    'valid_before': msgcopy.get_int64(),
    'critical_options': msgcopy.get_list(),
    'extensions': msgcopy.get_list(),
    'reserved': msgcopy.get_string(),
    'signature_key': msgcopy.get_string(),
    'signature': Message(msgcopy.get_string()),    
}

import sys
# print(decoded['principals'])
# print(principals.asbytes())
# sys.exit()

principals = Message()
principals.add_string('root')
principals.add_string('rooter')
principals.add_string('rootest')

ext = Message()
ext.add_string('permit-X11-forwarding')
ext.add_string('')
ext.add_string('permit-agent-forwarding')
ext.add_string('')

# Target public key
with open('testcerts/ecdsa_user.pub', 'r') as f:
    pubf = f.read().split(' ')
    nom = pubf[0]
    certbytes = Message(b64decode(pubf[1]))
    _ = certbytes.get_string()
    _ = certbytes.get_string()
    publickey = certbytes.get_string()

# Signature public key
with open('testcerts/ecdsa_ca.pub', 'r') as f:
    pubf = f.read().split(' ')[1]
    sigpub = b64decode(pubf)


# print(decoded['public_key'])
# print(nom)
# print(certbytes)
# print(decoded['signature_key'])
# sys.exit()

recode = Message()
recode.add_string('ecdsa-sha2-nistp256-cert-v01@openssh.com')
recode.add_string('abcdefghijklmnopqrstuvwxyz')
recode.add_string('nistp256')
recode.add_string(publickey)
recode.add_int64(16912)
recode.add_int(1)
recode.add_string('mydamnkey')
recode.add_string(principals.asbytes())
recode.add_int64(int(time()))
recode.add_int64(int(time()+(3600*12)))
recode.add_list([])
recode.add_string(ext.asbytes())
recode.add_string('')
recode.add_string(sigpub)

signed = pkey.sign_ssh_data(recode.asbytes())
recode.add_string(signed)


with open('testerr.pub', 'w') as f:
    f.write(f'ecdsa-sha2-nistp256-cert-v01@openssh.com {b64encode(recode.asbytes()).decode("utf-8")} User@Host\n')

