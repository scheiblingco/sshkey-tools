# from src.sshkey_tools.cert import main


# import os
# from datetime import datetime, timedelta
# from src.sshkey_tools.fields import CERT_TYPE
# import src.sshkey_tools.cert as _CERT
# import src.sshkey_tools.keys as _KEYS

# rsa_ca = _KEYS.RSAPrivateKey.generate(1024)
# dsa_ca = _KEYS.DSAPrivateKey.generate(1024)
# ecdsa_ca = _KEYS.ECDSAPrivateKey.generate(_KEYS.EcdsaCurves.P256)
# ed25519_ca = _KEYS.ED25519PrivateKey.generate()

# rsa_user = _KEYS.RSAPrivateKey.generate(1024).public_key
# dsa_user = _KEYS.DSAPrivateKey.generate(1024).public_key
# ecdsa_user = _KEYS.ECDSAPrivateKey.generate(_KEYS.EcdsaCurves.P384).public_key
# ed25519_user = _KEYS.ED25519PrivateKey.generate().public_key

# now = datetime.now()
# then = datetime.now() + timedelta(hours=12)

# cert_details = {
#     'serial': 1234567890,
#     'cert_type': CERT_TYPE.USER.value,
#     'key_id': 'KeyIdentifier',
#     'principals': [
#         'Good',
#         'Morning',
#         'Starshine'
#     ],
#     'valid_after': now,
#     'valid_before': then,
#     'critical_options': [],
#     'extensions': [
#         'permit-agent-forwarding'
#     ]
# }



# pubkeys = [
#     {
#         'file': rsa_user,
#         'file2': rsa_ca,
#         'type': _CERT.RSACertificate
#     },
#     {
#         'file': dsa_user,
#         'file2': dsa_ca,
#         'type': _CERT.DSACertificate
#     },
#     {
#         'file': ecdsa_user,
#         'file2': ecdsa_ca,
#         'type': _CERT.ECDSACertificate
#     },
#     {
#         'file': ed25519_user,
#         'file2': ed25519_ca,
#         'type': _CERT.ED25519Certificate
#     }
# ]

# privkeys = [
#     rsa_ca,
#     dsa_ca,
#     ecdsa_ca,
#     ed25519_ca
# ]

# for item in pubkeys:
#     for ca in privkeys:
#         cert = item['type'](
#             item['file'],
#             ca,
#             **cert_details
#         )
#         cert.sign()
#         cert.to_file('testcert')

#         cert = _CERT.SSHCertificate.from_file('testcert')
#         print(cert)

#         if os.system('ssh-keygen -Lf testcert') != 0:
#             raise Exception('Failed to verify testcert')

        