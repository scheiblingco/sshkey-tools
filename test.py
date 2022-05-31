import os
import unittest
import random
import datetime
import faker

import src.sshkey_tools.keys as _KEY
import src.sshkey_tools.fields as _FIELD
import src.sshkey_tools.cert as _CERT
import src.sshkey_tools.exceptions as _EX

ll = [
    'permit-x11-forwarding',
    'permit-pty'
]

# print(_FIELD.StandardListField.encode(ll))
# print(_FIELD.KeyValueField.encode(ll))
# print(_FIELD.SeparatedListField.encode(ll))

cert_opts = {
    'serial': 1234567890,
    'cert_type': _FIELD.CERT_TYPE.USER,
    'key_id': 'KeyIdentifier',
    'principals': [
        'pr_a',
        'pr_b',
        'pr_c'
    ],
    'valid_after': 1968491468,
    'valid_before': 1968534668,
    'critical_options': {
        'force-command': 'sftp-internal',
        'source-address': '1.2.3.4/8,5.6.7.8/16',
        'verify-required': ''
    },
    'extensions': [
        'permit-agent-forwarding',
        'permit-X11-forwarding'
    ]
}

user_pub = _KEY.RSAPrivateKey.generate(1024).public_key
ca_priv = _KEY.RSAPrivateKey.generate(1024)

cert = _CERT.SSHCertificate.from_public_class(user_pub, ca_priv, **cert_opts)

cert.sign()
cert.to_file('test_certificate')

cert2 = _CERT.SSHCertificate.from_file('test_certificate')

assert cert.get_signable_data() == cert2.get_signable_data()

print("Hold")


# cert = _CERT.RSACertificate(
#     user_pub,
#     ca_priv,
#     **cert_opts
# )
# cert.sign()

# cert.to_file('test_certificate')
# cert2 = _CERT.SSHCertificate.from_file('test_certificate')

# print(cert2)

# # print(cert2.fields['critical_options'].value)
# # print(cert2.fields['extensions'].value)



# os.system('ssh-keygen -Lf test_certificate')



# print((datetime.now() + timedelta(weeks=52*10)).timestamp())
# print((datetime.now() + timedelta(weeks=52*10, hours=12)).timestamp())

# _FLD.BooleanField.encode('Hello')

# test = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
# test2 = [b'a', b'b', b'c', b'd', b'e', b'f', b'g']

# field = _FLD.SeparatedListField(test)
# field2 = _FLD.SeparatedListField(test2)

# by = bytes(field)
# by2 = bytes(field)

# fieldout = _FLD.SeparatedListField.decode(by)[0]
# fieldout2 = _FLD.SeparatedListField.decode(by2)[0]

# print("Hold")

# allowed_values = (
#             "ssh-rsa-cert-v01@openssh.com",
#             "rsa-sha2-256-cert-v01@openssh.com",
#             "rsa-sha2-512-cert-v01@openssh.com",
#             "ssh-dss-cert-v01@openssh.com",
#             "ecdsa-sha2-nistp256-cert-v01@openssh.com",
#             "ecdsa-sha2-nistp384-cert-v01@openssh.com",
#             "ecdsa-sha2-nistp521-cert-v01@openssh.com",
#             "ssh-ed25519-cert-v01@openssh.com",
#         )

# for value in allowed_values:
#     print(f''' ('{value}', {_FLD.PubkeyTypeField.encode(value)}) ''')

# randomized = _FLD.NonceField()
# randomized.value
        
# print(_FLD.BooleanField.encode(False))
# print(_FLD.BooleanField.encode(True))

# test = True
# test = not test
# print(test)

# rsa = RSAPrivateKey.generate()
# dsa = DSAPrivateKey.generate()
# ecdsa = ECDSAPrivateKey.generate()
# ed25519 = ED25519PrivateKey.generate()



# data = b'Hello World'

# rsa = PrivateKey.from_string('''-----BEGIN OPENSSH PRIVATE KEY-----\n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\n-----END OPENSSH PRIVATE KEY-----\n''')
# dsa = PrivateKey.from_string('''-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZHNzAAAA\ngQD8R6aUzO+egB6wdIe/mclkiZ3fvIiPOseBHuradx5GSujuNQNqZuy9CIPfDmNjjyyLLKleaIn8\nLMb8DGVSDgKOoNGTWuTwQ6kjA50jDJzMgL/fzlYPyArvr6sIH287FZkp506rRERHUyHAxY407sqw\n5zJ/adhHAFOYSWmFvJOc2wAAABUApA6ZZMbc6qS4CBCAWWekCcYFLdcAAACAfuEuvf7h1rx0kK+D\nOU3POGAdWP4IVQfcwFOQoi6M4etM7CpfBgIl1j1ZwSi0E56uiB+gST1rY/P0xVUbFtUd0VbpJrkQ\n1AWb/Jb+oElwgaEYUi11exMvyRzwCGpOX4fPmqiQZXXtdF4Ba5KwGoxmmN4eGgoqhx9EoD7fxWqQ\n3hEAAACAS7cdXTTEw5hpkNr757fV2M4zH0/CMjvKCvAUbZZgeuZpQ0frFlaFAneG3BeMMlYqbtEE\n4mBOPGNe58VJovb9ANAE3kVkZUbnZF8ofCKyam7vp0jRMqd/QQvRrSEVo/yb4d9QHoQ15Y1ZxbRK\nxvaiKEt0pnC4/9GwMM+SfhLatdoAAAHYd4p1QHeKdUAAAAAHc3NoLWRzcwAAAIEA/EemlMzvnoAe\nsHSHv5nJZImd37yIjzrHgR7q2nceRkro7jUDambsvQiD3w5jY48siyypXmiJ/CzG/AxlUg4CjqDR\nk1rk8EOpIwOdIwyczIC/385WD8gK76+rCB9vOxWZKedOq0RER1MhwMWONO7KsOcyf2nYRwBTmElp\nhbyTnNsAAAAVAKQOmWTG3OqkuAgQgFlnpAnGBS3XAAAAgH7hLr3+4da8dJCvgzlNzzhgHVj+CFUH\n3MBTkKIujOHrTOwqXwYCJdY9WcEotBOerogfoEk9a2Pz9MVVGxbVHdFW6Sa5ENQFm/yW/qBJcIGh\nGFItdXsTL8kc8AhqTl+Hz5qokGV17XReAWuSsBqMZpjeHhoKKocfRKA+38VqkN4RAAAAgEu3HV00\nxMOYaZDa++e31djOMx9PwjI7ygrwFG2WYHrmaUNH6xZWhQJ3htwXjDJWKm7RBOJgTjxjXufFSaL2\n/QDQBN5FZGVG52RfKHwismpu76dI0TKnf0EL0a0hFaP8m+HfUB6ENeWNWcW0Ssb2oihLdKZwuP/R\nsDDPkn4S2rXaAAAAFCLiyWA/bpyBew4ZTgniE3LzEdmTAAAAAAECAw==\n-----END OPENSSH PRIVATE KEY-----\n''')
# ecdsa = PrivateKey.from_string('''-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS1zaGEy\nLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQBmnxyVUU1ZALvV6pVwIOr0E6qUAXh4+7fpmFV71YP\nzhoeim7u+AtnaNYSEBvnEcogK9IQXJ3bjkWbYQuQJhWVG+0B5AEgUnZAnEmklN+MlxV+Iam15vJV\n4dQSfdSWnOu6iz04pWpSBTTKQyd/PpoxrgNoQ1ZY4FwFptYHrtm+xHGEkmcAAAEADxJkPw8SZD8A\nAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQAAAIUEAZp8clVFNWQC71eqVcCDq9BO\nqlAF4ePu36ZhVe9WD84aHopu7vgLZ2jWEhAb5xHKICvSEFyd245Fm2ELkCYVlRvtAeQBIFJ2QJxJ\npJTfjJcVfiGptebyVeHUEn3Ulpzruos9OKVqUgU0ykMnfz6aMa4DaENWWOBcBabWB67ZvsRxhJJn\nAAAAQgG80oMoSfdQpLDNHJLmJqGt29TF+t5961uU//nJqVRgOwNfR52urpQf0shljtvWNhdNkab9\nn55bYQhTPSIjqj47jwAAAAABAg==\n-----END OPENSSH PRIVATE KEY-----\n''')
# ed25519 = PrivateKey.from_string('''-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx\nOQAAACDogQjCZHK2fnTSnuoaI8ZlkrwntznXOrr628xfZPHUJAAAAIgX9FhFF/RYRQAAAAtzc2gt\nZWQyNTUxOQAAACDogQjCZHK2fnTSnuoaI8ZlkrwntznXOrr628xfZPHUJAAAAED0ZjfmuHF9M5kh\n0U5tCgKgVNvKZem6HPkpyY0DLTkjZeiBCMJkcrZ+dNKe6hojxmWSvCe3Odc6uvrbzF9k8dQkAAAA\nAAECAwQF\n-----END OPENSSH PRIVATE KEY-----\n''')

# signatures = [
#             {
#                 'data': b'@OW=KT:J?KI32=;V3^`=',
#                 'rsa': '',
#                 'dsa': '',
#                 'ecdsa': '',
#                 'ed25519': ''
#             },
#             {
#                 'data': b'>_TVGM:bM77NG8O=Lab7',
#                 'rsa': '',
#                 'dsa': '',
#                 'ecdsa': '',
#                 'ed25519': ''
#             },
#             {
#                 'data': b'>bH[LNFG7=cNcEYJ;TEN',
#                 'rsa': '',
#                 'dsa': '',
#                 'ecdsa': '',
#                 'ed25519': ''
#             },
#             {
#                 'data': b'^Z`KVX@:XL:6?`@TYcOX',
#                 'rsa': '',
#                 'dsa': '',
#                 'ecdsa': '',
#                 'ed25519': ''
#             },
#             {
#                 'data': b'N[U4\<caSGF3O25EdS4b',
#                 'rsa': '',
#                 'dsa': '',
#                 'ecdsa': '',
#                 'ed25519': ''
#             },
#             {
#                 'data': b'7:U5T2`DU<J>=>:5;bPD',
#                 'rsa': '',
#                 'dsa': '',
#                 'ecdsa': '',
#                 'ed25519': ''
#             }
#         ]

# from base64 import b64encode

# for item in signatures:
#     rsa_sig = b64encode(rsa.sign(item['data']))
#     dsa_sig = b64encode(dsa.sign(item['data']))
#     ecdsa_sig = b64encode(ecdsa.sign(item['data']))
#     ed25519_sig = b64encode(ed25519.sign(item['data']))
    
#     print(f'''
#               'data': {item['data']},
#               'rsa': {rsa_sig},
#               'dsa': {dsa_sig},
#               'ecdsa': {ecdsa_sig},
#               'ed25519': {ed25519_sig}
#     ''')



# a = privatekey.sign(data)
# for _ in range(10):
#     b = privatekey.sign(data)
#     assert a == b

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

        