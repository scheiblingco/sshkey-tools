from src.sshkey_tools import (
    fields as _F,
    keys as _K,
    exceptions as _E,
    signatures as _S
)
rsa_pub = _K.PublicKey.from_file('testkeys/id_rsa.pub')
rsa_priv = _K.PrivateKey.from_file('testkeys/id_rsa')
ecdsa_pub = _K.PublicKey.from_file('testkeys/id_ecdsa.pub')
ecdsa_priv = _K.PrivateKey.from_file('testkeys/id_ecdsa')
ed25519_pub = _K.PublicKey.from_file('testkeys/id_ed25519.pub')
ed25519_priv = _K.PrivateKey.from_file('testkeys/id_ed25519')

rsa_data = open('testkeys/rsa.txt', 'rb').read()
ecdsa_data = open('testkeys/ecdsa.txt', 'rb').read()
ed25519_data = open('testkeys/ed25519.txt', 'rb').read()

signature_fields = _S.SignatureFieldset(
    hash_algorithm="sha512",
    namespace="hello@world"
)

# rsa_new_sig = _S.SSHSignature(rsa_priv, signature_fields)
# rsa_new_sig.sign(rsa_data)
# rsa_new_sig.to_file('testkeys/rsa.txt.sig2')

ecdsa_new_sig = _S.SSHSignature(ecdsa_priv, signature_fields)
ecdsa_new_sig.sign(ecdsa_data)
ecdsa_new_sig.to_file('testkeys/ecdsa.txt.sig2')

# ed25519_new_sig = _S.SSHSignature(ed25519_priv, signature_fields)
# ed25519_new_sig.sign(ed25519_data)
# ed25519_new_sig.to_file('testkeys/ed25519.txt.sig')

# Validate files created with ssh-keygen (WORKS!)
# rsa_sign = _S.SSHSignature.from_file('testkeys/rsa.txt.sig')
# rsa_sign2 = _S.SSHSignature.from_file('testkeys/rsa.txt.sig2')
print(1)
ecdsa_sign = _S.SSHSignature.from_file('testkeys/ecdsa.txt.sig')
print(2)
ecdsa_sign2 = _S.SSHSignature.from_file('testkeys/ecdsa.txt.sig2')
print(3)
ed25519_sign = _S.SSHSignature.from_file('testkeys/ed25519.txt.sig')

rsa_sign.verify(rsa_data)
rsa_sign2.verify(rsa_data)
ecdsa_sign.verify(ecdsa_data)
ed25519_sign.verify(ed25519_data)


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
