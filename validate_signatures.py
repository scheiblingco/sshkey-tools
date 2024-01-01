from src.sshkey_tools import (
    fields as _F,
    keys as _K,
    exceptions as _E,
    signatures as _S
)

# Load public and private keys
rsa_priv = _K.PrivateKey.from_file('testkeys/id_rsa')
ecdsa_priv = _K.PrivateKey.from_file('testkeys/id_ecdsa')
ed25519_priv = _K.PrivateKey.from_file('testkeys/id_ed25519')
rsa_pub = rsa_priv.public_key
ecdsa_pub = ecdsa_priv.public_key
ed25519_pub = ed25519_priv.public_key

# Load externally created signatures
rsa_sign = _S.SSHSignature.from_file('testkeys/rsa.txt.sig')
ecdsa_sign = _S.SSHSignature.from_file('testkeys/ecdsa.txt.sig')
ed25519_sign = _S.SSHSignature.from_file('testkeys/ed25519.txt.sig')

# Load the data used for the signatures
rsa_data = open('testkeys/rsa.txt', 'rb').read()
ecdsa_data = open('testkeys/ecdsa.txt', 'rb').read()
ed25519_data = open('testkeys/ed25519.txt', 'rb').read()

rsa_signable = rsa_sign.get_signable_file('testkeys/rsa.txt')
ecdsa_signable = ecdsa_sign.get_signable_file('testkeys/ecdsa.txt')
ed25519_signable = ed25519_sign.get_signable_file('testkeys/ed25519.txt')

# try:
# ecdsa_pub.verify(ecdsa_signable, ecdsa_sign.fields.signature.value)
# ecdsa_pub.to_file('testkeys/ecdsa.txt.sig2')
rsa_pub.verify(rsa_signable, rsa_sign.fields.signature.value)
rsa_sign.to_file('testkeys/rsa.txt.sig2')
# except:
    # print("RSA validation failed")

try:
    ecdsa_pub.verify(ecdsa_signable, ecdsa_sign.fields.signature.value)
    ecdsa_sign.to_file('testkeys/ecdsa.txt.sig2')
except:
    print("ECDSA validation failed")

try:
    ed25519_pub.verify(ed25519_signable, ed25519_sign.fields.signature.value)
    ed25519_sign.to_file('testkeys/ed25519.txt.sig2')
except:
    print("Ed25519 validation failed")



try:
    rsasig = _S.SSHSignature(rsa_priv)
    rsasig.sign(rsa_data)
    rsa_pub.verify(rsasig.get_signable(rsa_data), rsasig.fields.signature.value)
except:
    print("RSA validation after signing failed")

try:
    ecdsasig = _S.SSHSignature(ecdsa_priv)
    ecdsasig.sign(ecdsa_data)
    ecdsa_pub.verify(ecdsasig.get_signable(ecdsa_data), ecdsasig.fields.signature.value)
except:
    print("ECDSA validation after signing failed")

try:
    ed25519sig = _S.SSHSignature(ed25519_priv)
    ed25519sig.sign(ed25519_data)
    ed25519_pub.verify(ed25519sig.get_signable(ed25519_data), ed25519sig.fields.signature.value)
except:
    print("Ed25519 validation after signing failed")
