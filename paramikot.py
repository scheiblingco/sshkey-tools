from paramiko.message import Message
from paramiko.ecdsakey import ECDSAKey
from base64 import b64encode, b64decode
from time import time

with open('testcerts/ecdsa_user.pub', 'r') as f:
    cont = f.read().split(' ')
    
test = Message(b64decode(cont[1]))

print(test.asbytes())
print(b64decode(cont[1]))

print(test.get_string())
print(test.get_string())
print(test.get_string())


# test = Message()
# test.add_string('root')
# test.add_string('rooter')
# test.add_string('rootest')
# # test.add_list([b'root', b'rooter', b'rootest'])
# print(test.asbytes())
# # Add key type
# # test.add_string('ecdsa-sha2-nistp256-cert-v01@openssh.com')

# # Add nonce
# test.add_string('abcdefghijklmnop')

# # Add curve
# test.add_string('nistp256')

# # Add public_key
# with open('testcerts/ecdsa_user.pub', 'r') as f:
#     pke = f.read().split(' ')[1]
    
# test.add_string(b64decode(pke))

# # Add serial
# test.add_int64(123456)

# # Add type
# test.add_int(1)

# # Add key_id
# test.add_string('mfdutra')

# # Add valid principals
# test.add_list(['root', 'rooter', 'rootest'])

# # Add valid after
# test.add_int64(int(time()))

# # Add valid before
# test.add_int64(int(time() + (3600*12)))

# # Add critical options
# test.add_list([])

# # Add extensions
# test.add_list(['permit-X11-forwarding', 'permit-agent-forwarding'])

# # Add reserved
# test.add_string('')

# # Add signature key
# with open('testcerts/ecdsa_ca.pub', 'r') as f:
#     fl = f.read().split(' ')[1]
    
#     test.add_string(b64decode(fl))
    
# # Add signature
# ## Load key
# priv = ECDSAKey.from_private_key_file(filename='testcerts/ecdsa_ca')
# print(priv.can_sign())

# ## Sign message bytes
# signed = priv.sign_ssh_data(test.asbytes())



# newtest = Message()
# newtest.add_string('ecdsa-sha2-nistp256-cert-v01@openssh.com')
# newtest.add_bytes(test.asbytes())
# newtest.add_bytes(signed.asbytes())

# with open('testgen_cert', 'w') as f:
#     f.write('ecdsa-sha2-nistp256-cert-v01@openssh.com' + ' ' + b64encode(newtest.asbytes()).decode('utf-8') + ' ' + 'User@Host')

# stc = bytes(signed.asbytes())
# print(stc)
