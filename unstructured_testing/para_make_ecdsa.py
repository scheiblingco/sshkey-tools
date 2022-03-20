# Generate an ECDSA SSH Certificate according to:
# https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD

import os
import random
from time import time
from base64 import b64encode, b64decode
from paramiko.message import Message
from paramiko.ecdsakey import ECDSAKey


# Create SSH User certificate message
certificate = Message()

# Add the certificate type
certificate.add_string('ecdsa-sha2-nistp256-cert-v01@openssh.com')

# Add the nonce
certificate.add_string(str(random.randint(2**10, 2**32)))

# Add the curve
certificate.add_string('nistp256')

# Add the user public key
# Here, we only want the certificate bytes and not the whole object with
# identifiers in front, e.g. ssh-ecdsa-nistp256 or nistp256 since those are
# already defined above

with open('testcerts/ecdsa_user.pub', 'r') as f:
    user_key = f.read().split(' ')[1]
    user_key = Message(b64decode(user_key))
    _ = user_key.get_string()
    _ = user_key.get_string()
    user_key = user_key.get_string()
certificate.add_string(user_key)

# Add the serial number (numeric)
certificate.add_int64(123456)

# Add the certificate type (1=User, 2=Host)
certificate.add_int(1)

# Add the key ID (alphanumeric, e.g. identifier)
certificate.add_string('abcdefgh')

# Add the valid principals for the certificate (custom list)
principal_list = Message()
principal_list.add_string('root')
principal_list.add_string('regular_user')
principal_list.add_string('irregular_user')

certificate.add_string(principal_list.asbytes())

# Add the valid after timestamp (now)
certificate.add_int64(int(time()))

# Add the valid before timestamp (12 hours)
certificate.add_int64(int(time() + (3600 * 12) ))

# Add critical options (empty list)
certificate.add_list([])

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

certificate.add_string(extension_list.asbytes())

# Add the the reserved part (currently unused by spec)
certificate.add_string('')

# Add the signature public key
# This is the full public key including identifier and curve
with open('testcerts/ecdsa_ca.pub', 'r') as f:
    ca_pubkey = f.read().split(' ')[1]
    ca_pubkey = b64decode(ca_pubkey)

certificate.add_string(ca_pubkey)

# Finally, add the signature
# Load the CA private key
ca_key = ECDSAKey.from_private_key_file('testcerts/ecdsa_ca')

# Sign the current certificate data
signature = ca_key.sign_ssh_data(certificate.asbytes())

# Add the signature to the bottom of the certificate
certificate.add_string(signature)

# Write the certificate to a file
# with open('testcerts/ecdsa_user-cert.pub', 'w') as f:
#     f.write(
#         # Certificate format identifier
#         'ecdsa-sha2-nistp256-cert-v01@openssh.com ' +
#         b64encode(certificate.asbytes()).decode('utf-8') +
#         ' User@Host\n'
#     )

with open('testcerts/ecdsa_user-cert.pub', 'wb') as f:
    f.write(
        b'ecdsa-sha2-nistp256-cert-v01@openssh.com ' +
        b64encode(certificate.asbytes()) +
        b' user@host'
    )

# Finally, verify the certificate has been correctly created
print(os.system('ssh-keygen -Lf testcerts/ecdsa_user-cert.pub'))
