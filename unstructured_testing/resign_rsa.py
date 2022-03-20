from base64 import b64encode, b64decode
from struct import pack, unpack

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.asymmetric import utils


def decodeUint32(value):
  return int(unpack('>I', value[:4])[0]), value[4:]

def decodeUint64(value):
  return int(unpack('>Q', value[:8])[0]), value[8:]

def decodeMpint(value):
  size = unpack('>I', value[:4])[0]
  return None, value[size:]

def decodeString(value):
  size = unpack('>I', value[:4])[0]+4
  return value[4:size], value[size:]

def decodeList(value):
  joined, remaining = decodeString(value)
  list = []
  while len(joined) > 0:
    elem, joined = decodeString(joined)
    list.append(elem)
  return list, remaining

def encodeString(string):
    return pack('>I', len(string)) + string

def encodeList(lst):
    return pack('>I', len(lst)) + b''.join(lst)

def encodeUint64(num):
    try:
        return pack('>Q', num)
    except:
        print(num)
        raise ValueError

def encodeUint32(num):
    return pack('>I', num)

def encodeMpint(num):
    return pack('>I', len(num)) + num


rsaFormat = [
  (decodeString, "cert_type"),
  (decodeString, "nonce"),
  (decodeString,  "e"),
  (decodeString,  "n"),
  (decodeUint64, "serial"),
  (decodeUint32, "type"),
  (decodeString, "key id"),
  (decodeString, "valid principals"),
  (decodeUint64, "valid after"),
  (decodeUint64, "valid before"),
  (decodeString, "critical options"),
  (decodeString, "extensions"),
  (decodeString, "reserved"),
  (decodeString, "signature key"),
  (decodeString, "signature"),
]


reencode = [
#   (encodeString, "cert_type"),
  (encodeString, "nonce"),
  (encodeString,  "e"),
  (encodeString,  "n"),
  (encodeUint64, "serial"),
  (encodeUint32, "type"),
  (encodeString, "key id"),
  (encodeString, "valid principals"),
  (encodeUint64, "valid after"),
  (encodeUint64, "valid before"),
  (encodeString, "critical options"),
  (encodeString, "extensions"),
  (encodeString, "reserved"),
  (encodeString, "signature key"),
#   (decodeString, "signature"),
]

def Decode(encoded):
    binde = b64decode(encoded)
    
    r = {}
    for typ, key in rsaFormat:
        val, binde = typ(binde)
        r[key] = val
        
    return r


with open('testcerts/rsa_user-cert.pub', 'r') as f:
    cert = f.read().split(' ')
    
    
    
    
decoded = Decode(cert[1])
# print(decoded)
old = b64decode(cert[1])

ctype = b'ssh-rsa-cert-b01@openssh.com'
bin = encodeString(ctype)

for func, val in reencode:
    additive = func(decoded[val])
    bin = bin + additive



print(bin)
print(old)


# chosen_hash = hashes.SHA256()
# hasher = hashes.Hash(chosen_hash)   

# ctype = b'ecdsa-sha2-nistp256-cert-v01@openssh.com'
# # ctype = decoded['nonce']
# bin = encodeString(ctype)
# hasher.update(bin)

# for func, val in reencode:
#     additive = func(decoded[val])
#     hasher.update(additive)
#     bin = bin + additive
    

# with open('ssh_ca', 'rb') as f:
#     ca = f.read()
    
# keydata = crypto_serialization.load_pem_private_key(
#     data=ca,
#     password=None,
#     backend=crypto_default_backend()
# )
# digest = hasher.finalize()

# funcs = [
#     (hashes.SHA1, 'hashes.SHA1'),
#     (hashes.SHA256, 'hashes.SHA256'),
#     (hashes.SHA224, 'hashes.SHA224'),
#     (hashes.SHA384, 'hashes.SHA384'),
#     (hashes.SHA512, 'hashes.SHA512'),
#     (hashes.SHA512_224, 'hashes.SHA512_224'),
#     (hashes.SHA512_256, 'hashes.SHA512_256'),
#     (hashes.SHA3_224,  'hashes.SHA3_224,'),
#     (hashes.SHA3_384, 'hashes.SHA3_384'),
#     (hashes.SHA3_512, 'hashes.SHA3_512'),
#     (hashes.SHAKE128, 'hashes.SHAKE128'),
#     (hashes.SHAKE256, 'hashes.SHAKE25')
# ]


# for hashfunc, name in funcs:
#     signature = keydata.sign(
#         bin,
#         ec.ECDSA(hashfunc())
#     )
    
#     bin = bin + encodeString(encodeString(b'ecdsa-sha2-nistp251') + encodeString(signature))
    
#     with open(f'testcerts/{name}', 'w') as f:
#         f.write(f'ecdsa-sha2-nistp251 {b64encode(bin).decode("utf-8")} user@host')




# # for hashfunc, name in funcs:
    
#     # # try:
#     # print(keydata.public_key().verify(
#     #     decoded['signature'],
#     #     digest,
#     #     ec.ECDSA(hashfunc())
#     # ))
#     # # except:
#     # #     print("Error validating signature")

# # keydata.public_key().verify(
# #     decoded['signature'][1],
# #     bin,
# #     ec.ECDSA(hashes.SHA1())
# # )


# # signature = keydata.sign(
# #     bin,
# #     ec.ECDSA(hashes.SHA384())
# # )
# # print(utils.decode_dss_signature(signature))
# # bin = bin + encodeString(encodeString(b'ecdsa-sha2-nistp521') + encodeString(signature))

# # with open('test_cert_2', 'w') as f:
# #     f.write('ecdsa-sha2-nistp512-cert-v01@openssh.com' + ' ' + b64encode(bin).decode('iso-8859-1') + ' ' + 'User@Host')
# # print(decoded['signature'])
# # print(signature)
    
# # print(bin)
# # print("\n\n")
# # print(b64encode(bin))
# # print("\n\n")
# # print(cert[1])
# # print("\n\n")
# # print(cert[1].encode('iso-8859-1') == b64encode(bin))



# # print(b64decode(cert[1])[0:90])
# # tster2 = b'\xfb\x1dQ\x10\xf7 \xe0=\xb2<C\x8f)\xa7\x92\x80*g\x05\xb3?+\xa2\xc4u\x182*\xedB\x0e\xed'
# # test = pack('>I', len(tster)) + tster
# # print(test)
# # print(test+tster)
# test = test + pack('>I', len(tster2)) + tster2

# print(test)