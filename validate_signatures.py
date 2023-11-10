from src.sshkey_tools import (
    fields as _F,
    keys as _K,
    exceptions as _E,
    signatures as _S
)


# Validate files created with ssh-keygen (WORKS!)
rsa_pub = _K.PublicKey.from_file('testkeys/id_rsa.pub')
ecdsa_pub = _K.PublicKey.from_file('testkeys/id_ecdsa.pub')
ed25519_pub = _K.PublicKey.from_file('testkeys/id_ed25519.pub')

rsa_sign = _S.SSHSignature.from_file('testkeys/rsa.txt.sig')
ecdsa_sign = _S.SSHSignature.from_file('testkeys/ecdsa.txt.sig')
ed25519_sign = _S.SSHSignature.from_file('testkeys/ed25519.txt.sig')

rsa_data = open('rsa.txt', 'rb').read()
ecdsa_data = open('ecdsa.txt', 'rb').read()
ed25519_data = open('ed25519.txt', 'rb').read()

rsa_signable = rsa_sign.get_signable(rsa_data)
ecdsa_signable = ecdsa_sign.get_signable(ecdsa_data)
ed25519_signable = ed25519_sign.get_signable(ed25519_data)

try:
    rsa_pub.verify(rsa_signable, rsa_sign.fields.signature.value)
except:
    print("RSA validation failed")

try:
    ecdsa_pub.verify(ecdsa_signable, ecdsa_sign.fields.signature.value)
except:
    print("ECDSA validation failed")

try:
    ed25519_pub.verify(ed25519_signable, ed25519_sign.fields.signature.value)
except:
    print("Ed25519 validation failed")

print()
