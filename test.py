from src.sshkey_tools.cryptography import PublicKey, PublicKeyTypes, RSAPublicKey, ECDSAPublicKey, DSAPublicKey, ED25519PublicKey

# for type in PublicKeyTypes:
#     print(type)

from base64 import b64decode
with open('test_dsa.pub', 'rb') as f:
    dsa_pubkey = f.read()
    split = dsa_pubkey.split(b' ')[2]
    decoded = b64decode(split)
    test, decoded = utils.decode_string(decoded)

# test = PublicKey.from_file('testcert')
# test2 = PublicKey.from_file('test_dsa.pub')
# test3 = PublicKey.from_file('test_rsa_key.pub')
# test4 = PublicKey.from_file('test_ed25519.pub')
# print(type(test))
# print(type(test2))
# print(type(test3))
# print(type(test4))

# # # pylint: disable-all
# from src.sshkey_tools.utils import *
# from base64 import b64decode, b64encode
# from time import time
# from cryptography.hazmat.backends import default_backend
# import src.sshkey_tools.fields as fields


# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
# from cryptography.hazmat.primitives.asymmetric import padding


# cert = []

# cert.append(fields.StringField('rsa-sha2-512-cert-v01@openssh.com'))
# cert.append(fields.NonceField(64))

# with open('test_rsa_key.pub', 'rb') as f:
#     cert.append(fields.RSAUserPubkeyField(f.read()))

# cert.append(fields.Integer64Field(123456))
# cert.append(fields.CertificateTypeField(fields.CertificateType.USER))
# cert.append(fields.StringField('abcdefghijklmnopqrstuvwxyz'))
# cert.append(fields.PrincipalListField(['root', 'rooter', 'rootest']))
# cert.append(fields.TimeField())
# cert.append(fields.TimeField(12*3600))
# cert.append(fields.CriticalOptionsListField([]))
# cert.append(fields.ExtensionsListField(['permit-abc-forwarding']))
# cert.append(fields.StringField(''))
# cert.append(fields.StringField(cert[2].pubkey['raw_key']))

# cert_bytes = b''.join([bytes(x) for x in cert])

# with open('test_rsa_key', 'rb') as f:
#     ca_private_key = private_key_to_object(f.read())

# cert.append(fields.RSASignatureField(
#     rsa_sign_bytes(
#         cert_bytes,
#         ca_private_key
#     ),
#     'rsa-sha2-512'
# ))

# with open('testcert', 'w') as f:
#     f.write(get_certificate_file(
#         'rsa-sha2-512-cert-v01@openssh.com',
#         b''.join([bytes(x) for x in cert]),
#         'User@Host'
#     ))

# # Test verification
# print(cert[2].pubkey['key'].verify(
#     signature=cert[-1].value,
#     data=cert_bytes + b'\x12',
#     padding=padding.PKCS1v15(),
#     algorithm=hashes.SHA512()
# ))

# import os
# os.system('ssh-keygen -Lf testcert')
  
    
# # cert = b''
# # cert += fields.StringField('rsa-sha2-512-cert-v01@openssh.com').to_bytes()
# # cert += fields.NonceField(64).to_bytes()
# # cert += fields.RSAUserPubkeyField(user_pubkey).to_bytes()
# # cert += fields.Integer64Field(123456).to_bytes()
# # cert += fields.CertificateTypeField(fields.CertificateType.USER).to_bytes()
# # cert += fields.StringField('abcdefgh').to_bytes()
# # cert += fields.ListField(['root', 'otheruser']).to_bytes()
# # cert += bytes(fields.TimeField())
# # cert += bytes(fields.TimeField(3600*12))
# # cert += fields.ListField([], True).to_bytes()
# # cert += fields.ListField(['permit-X11-forwarding'], True).to_bytes()
# # cert += fields.StringField('').to_bytes()
# # cert += fields.StringField(ca_public_key['key']).to_bytes()

# # cert += fields.RSASignatureField(rsa_sign_bytes(
# #     data=cert,
# #     private_key=ca_private_key
# # )).to_bytes()

# # with open('test_rsa_user-cert2.pub', 'w') as f:
# #     f.write(
# #         get_certificate_file(
# #             type='rsa-sha2-512-cert-v01@openssh.com',
# #             data=cert,
# #             comment='User@Host'
# #         )
# #     )
# # import os
# # os.system('ssh-keygen -Lf test_rsa_user-cert2.pub')


# # # cert += encode_string('rsa-sha2-512-cert-v01@openssh.com')
# # # cert += encode_string(generate_secure_nonce(32))
# # # cert += encode_mpint(user_pubkey["key"].public_numbers().e)
# # # cert += encode_mpint(user_pubkey["key"].public_numbers().n)
# # # cert += encode_int64(1234567890)
# # # cert += encode_int(1)
# # # cert += encode_string('abcdefgh')
# # # cert += encode_list(['root', 'useracc'])
# # # cert += encode_int64(int(time()))
# # # cert += encode_int64(int(time() + (3600*12)))
# # # cert += encode_list([], True)
# # # cert += encode_list(['permit-X11-forwarding'], True)
# # # cert += encode_string('')
# # # cert += encode_string(ca_public_key['key'])

# # # cert += encode_rsa_signature(
# # #     rsa_sign_bytes(
# # #         data=cert,
# # #         private_key=ca_private_key
# # #     ),
# # #     "rsa-sha2-512"
# # # )

# # # with open('test_rsa_user-cert.pub', 'w') as f:
# # #     f.write(get_certificate_file(
# # #         type='rsa-sha2-512-cert-v01@openssh.com',
# # #         data=cert,
# # #         comment=user_pubkey["comment"]
# # #     ))
    
# # # import os
# # # os.system('ssh-keygen -Lf test_rsa_user-cert.pub')