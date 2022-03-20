# pylint: disable-all
# Generate a RSA SSH Certificate according to
# https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD

import os
import random
from time import time
from base64 import b64encode, b64decode
from paramiko.message import Message
from paramiko.ecdsakey import ECDSAKey


with open('testcerts/rsa_user-cert.pub') as f:
    cont = f.read().split(' ')[1]
    cert = Message(b64decode(cont))

decoded = {
    "type": cert.get_string(),
    "nonce": cert.get_string(),
    "e": cert.get_mpint(),
    "n": cert.get_mpint(),
    "serial": cert.get_int64(),
    "type": cert.get_int(),
    "key_id": cert.get_string(),
    "principals": cert.get_list(),
    "valid_after": cert.get_int64(),
    "valid_before": cert.get_int64(),
    "critical_options": cert.get_string(),
    "extensions": cert.get_string(),
    "reserved": cert.get_string(),
    "signer_key": cert.get_string(),
    "signature": cert.get_string()
}

encode = Message()

encode.add_string('ssh-rsa-cert-v01@openssh.com')
encode.add_string(decoded['nonce'])
encode.add_mpint(decoded['e'])
encode.add_mpint(decoded['n'])
encode.add_int64(123456)
encode.add_int(1)
encode.add_string('abcdefg')

# Principals
principal_list = Message()
principal_list.add_string('root')
principal_list.add_string('regular_user')
principal_list.add_string('irregular_user')

encode.add_string(principal_list.asbytes())

encode.add_int64(int(time()))
encode.add_int64(int(time() + (3600 * 12) ))
encode.add_string(decoded['critical_options'])
encode.add_string(decoded['extensions'])
encode.add_string('')

# Signing
with open('testcerts/ecdsa_ca.pub', 'r') as f:
    ca_pubkey = f.read().split(' ')[1]
    ca_pubkey = b64decode(ca_pubkey)

encode.add_string(ca_pubkey)

ca_key = ECDSAKey.from_private_key_file('testcerts/ecdsa_ca')
signature = ca_key.sign_ssh_data(encode.asbytes())
encode.add_string(signature)

with open('testcerts/ssh_user-cert.pub', 'wb') as f:
    f.write(
        b'ssh-rsa-cert-v01@openssh.com ' +
        b64encode(encode.asbytes()) +
        b' User@Host'
    )
    
os.system('ssh-keygen -Lf testcerts/ssh_user-cert.pub')