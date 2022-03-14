
import base64, json
from struct import unpack, pack

def Decode(base64encoded):
#   certType, bin = decodeString(base64.b64decode(base64encoded))
  bin = base64.b64decode(base64encoded)
  h = {}
  for typ, key in ecdsaFormat:
    val, bin = typ(bin)
    h[key] = str(val)
  return h


def decodeUint32(value):
  return int(unpack('>I', value[:4])[0]), value[4:]

def decodeUint64(value):
  return int(unpack('>Q', value[:8])[0]), value[8:]

def decodeMpint(value):
  size = int(unpack('>I', value[:4])[0])
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

rsaFormat = [
  (decodeString, "nonce"),
  (decodeMpint,  "e"),
  (decodeMpint,  "n"),
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

dsaFormat = [
  (decodeString, ),
  (decodeString, "nonce"),
  (decodeMpint,  "p"),
  (decodeMpint,  "q"),
  (decodeMpint,  "g"),
  (decodeMpint,  "y"),
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

ecdsaFormat = [
  (decodeString, "cert_type"),
  (decodeString, "nonce"),
  (decodeString, "curve"),
  (decodeString, "public_key"),
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

ed25519Format = [
  (decodeString, "nonce"),
  (decodeString, "pk"),
  (decodeUint64, "serial"),
  (decodeUint32, "type"),
  (decodeString, "key id"),
  (decodeList,   "valid principals"),
  (decodeUint64, "valid after"),
  (decodeUint64, "valid before"),
  (decodeString, "critical options"),
  (decodeString, "extensions"),
  (decodeString, "reserved"),
  (decodeString, "signature key"),
  (decodeString, "signature"),
]

formats = {
  "ssh-rsa-cert-v01@openssh.com":        rsaFormat,
  "ssh-dss-cert-v01@openssh.com":        dsaFormat,
  "ecdsa-sha2-nistp256-v01@openssh.com": ecdsaFormat,
  b"ecdsa-sha2-nistp256-cert-v01@openssh.com": ecdsaFormat,
  "ecdsa-sha2-nistp384-v01@openssh.com": ecdsaFormat,
  "ecdsa-sha2-nistp521-v01@openssh.com": ecdsaFormat,
  "ssh-ed25519-cert-v01@openssh.com":    ed25519Format,
}



def encodeString(string):
    return pack('>I', len(string)) + string.encode('iso-8859-1')

def encodeList(lst):
    return pack('>I', len(lst)) + b''.join(lst)

def encodeUint64(num):
    try:
        return pack('>Q', int(num))
    except:
        print(num)
        raise ValueError

def encodeUint32(num):
    return pack('>I', int(num))

def encodeMpint(num):
    return pack('>I', len(num)) + num


recode = [
  (encodeString, "cert_type"),
  (encodeString, "nonce"),
  (encodeString, "curve"),
  (encodeString, "public_key"),
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
  (encodeString, "signature"),
]

with open('ssh_user-cert.pub', 'r') as f:
    cert = f.read().split(' ')



decoded = Decode(cert[1])
reencoded = []

for func, val in recode:
    reencoded.append(func(decoded[val]))
    
ret = b''
for i in range(len(reencoded)):
    ret = ret + reencoded[i]

print(ret)

# reencode = []
# reencode.append( encodeString(decoded['cert_type']))
# reencode.append( encodeString(decoded['nonce']))
# reencode.append( encodeString(decoded['curve']))
# reencode.append( encodeString(decoded['public_key']))
# reencode.append( encodeUint64(654321))
# reencode.append( encodeUint64(1))
# reencode.append( encodeString(decoded['key id']))
# reencode.append( encodeString(decoded['valid principals']))
# reencode.append( encodeUint64(1647012660))
# reencode.append( encodeUint64(1647617534))
# reencode.append( encodeString(decoded['critical options']))
# reencode.append( encodeString(decoded['extensions']))
# reencode.append( encodeString(decoded['reserved']))
# reencode.append( encodeString(decoded['signature key']))
# reencode.append( encodeString(decoded['signature']))

reenc = b''

for x in reencoded:
    reenc = reenc+x


print(base64.b64encode(reenc) == cert[1])

print("Old: ")
print(cert[1])
# print(base64.b64decode(cert[1]))

print("New: ")
print(base64.b64encode(reenc))
# print(b''.join(reencode))
# print(decoded['serial'])
# reencode += encodeUint64(decoded['serial'])






# reencoded = b''
# for typ, key in recode:
#     reencoded += bytes(typ(decoded[key]))
    
# # encoded = b''.join([x[0](decoded[x[1]]) for x in decoded])
# print(reencoded)

# print(base64.b64encode(reencoded) == cert[1])