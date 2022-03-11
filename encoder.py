import base64
from struct import pack, unpack
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend as crypto_default_backend


with open('ssh_ca', 'rb') as f:
    keydata = crypto_serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=crypto_default_backend()
    )

with open('ssh_ca.pub', 'r') as f:
    user_pub = f.read()
    
# Get necessary data from user pubkey
stsz = lambda x: unpack('>I', x[:4])[0]+4
up_bin = base64.b64decode(user_pub.split(' ')[1])

_, up_bin = up_bin[4:stsz(up_bin)], up_bin[stsz(up_bin):]
_, up_bin = up_bin[4:stsz(up_bin)], up_bin[stsz(up_bin):]
ca_pub_only = up_bin[4:stsz(up_bin)]

with open('ssh_user.pub', 'r') as f:
    user_pub = f.read()
    
# Get necessary data from user pubkey
stsz = lambda x: unpack('>I', x[:4])[0]+4
up_bin = base64.b64decode(user_pub.split(' ')[1])

_, up_bin = up_bin[4:stsz(up_bin)], up_bin[stsz(up_bin):]
_, up_bin = up_bin[4:stsz(up_bin)], up_bin[stsz(up_bin):]
pub_only = up_bin[4:stsz(up_bin)]


def encodeString(string):
    return pack('>I', len(string)) + string

def encodeList(lst):
    return pack('>I', len(lst)) + b''.join(lst)

def encodeUint64(num):
    return pack('>Q', num)

def encodeUint32(num):
    return pack('>I', num)

def encodeMpint(num):
    return pack('>I', len(num)) + num


key_data = b''
key_data = key_data + encodeString(b'ecdsa-sha2-nistp256-cert-v01@openssh.com')
key_data = key_data + encodeString(b'abcdefghijklmnopqrstuvw')
key_data = key_data + encodeString(b'nistp256')
key_data = key_data + encodeString(ca_pub_only)
key_data = key_data + encodeUint64(654321)
key_data = key_data + encodeUint32(1)
key_data = key_data + encodeString(b'mfdutra')
key_data = key_data + encodeString(b'\x00\x00\x00\x04root\x00\x00\x00\x06rooter\x00\x00\x00\x07rootest\x00\x00\x00\x0croootoootooo')
key_data = key_data + encodeUint64(1647012660)
key_data = key_data + encodeUint64(1647617534)
key_data = key_data + encodeString(b'\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x17permit-agent-forwarding\x00\x00\x00\x00\x00\x00\x00\x16permit-port-forwarding\x00\x00\x00\x00\x00\x00\x00\npermit-pty\x00\x00\x00\x00\x00\x00\x00\x0epermit-user-rc\x00\x00\x00\x00')
key_data = key_data + encodeString(b'')
key_data = key_data + encodeString(pub_only)

to_sign = key_data

sig = keydata.sign(
    to_sign,
    ec.ECDSA(hashes.SHA256())
)

key_data = key_data + encodeString(b'ecdsa-sha2-nistp256-cert-v01@openssh.com' + b'\x00' + sig)  

to_write = base64.b64encode(key_data)
print(to_write)
with open('generated_key', 'wb') as f:
    f.write(b'ecdsa-sha2-nistp256-cert-v01@openssh.com' + b' ' + to_write + b' ' + b'user@host')

print(sig)