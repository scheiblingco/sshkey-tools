# sshkey-tools
Python and CLI tools for managing OpenSSH keypairs and certificates

# Installation
## With pip
```bash
pip3 install sshkey-tools
# or
pip3 install -e git+https://github.com/scheiblingco/sshkey-tools.git
```
## From source
```bash
git clone https://github.com/scheiblingco/sshkey-tools
cd sshkey-tools
pip3 install ./
```

# Documentation
[scheiblingco.github.io/sshkey-tools/](https://scheiblingco.github.io/sshkey-tools/)

# Basic usage
## SSH Keypairs
### Generate keys
```python
from sshkey_tools.keys import (
    RSAPrivateKey,
    DSAPrivateKey,
    ECDSAPrivateKey,
    ED25519PrivateKey,
    EcdsaCurves
)

# RSA
# By default, RSA is generated with a 4096-bit keysize
rsa_private = RSAPrivateKey.generate()

# You can also specify the key size
rsa_private = RSAPrivateKey.generate(bits)

# DSA
# Since OpenSSH only supports 1024-bit keys, this is the default
dsa_private = DSAPrivateKey.generate()

# ECDSA
# The default curve is P521
ecdsa_private = ECDSAPrivateKey.generate()

# You can also manually specify a curve
ecdsa_private = ECDSAPrivateKey.generate(EcdsaCurves.P256)

# ED25519
# The ED25519 keys are always a fixed size
ed25519_private = ED25519PrivateKey.generate()

# Public keys
# The public key for any given private key is in the public_key parameter
rsa_pub = rsa_private.public_key
```

### Load keys
You can load keys either directly with the specific key classes (RSAPrivateKey, DSAPrivateKey, etc.) or the general PrivateKey class
```python
from sshkey_tools.keys import (
    PrivateKey,
    PublicKey,
    RSAPrivateKey,
    RSAPublicKey
)

# Load a private key with a specific class
rsa_private = RSAPrivateKey.from_file('path/to/rsa_key')

# Load a private key with the general class
rsa_private = PrivateKey.from_file('path/to/rsa_key')
print(type(rsa_private))
"<class 'sshkey_tools.keys.RSAPrivateKey'>"

# Public keys can be loaded in the same way
rsa_pub = RSAPublicKey.from_file('path/to/rsa_key.pub')
rsa_pub = PublicKey.from_file('path/to/rsa_key.pub')

print(type(rsa_private))
"<class 'sshkey_tools.keys.RSAPrivateKey'>"

# Public key objects are automatically created for any given private key
# negating the need to load them separately
rsa_pub = rsa_private.public_key

# Load a key from a pyca/cryptography class privkey_pyca/pubkey_pyca
rsa_private = PrivateKey.from_class(privkey_pyca)
rsa_public = PublicKey.from_class(pubkey_pyca)

# You can also load private and public keys from strings or bytes (file contents)
with open('path/to/rsa_key', 'r', 'utf-8') as file:
    rsa_private = PrivateKey.from_string(file.read())

with open('path/to/rsa_key', 'rb') as file:
    rsa_private = PrivateKey.from_bytes(file.read())

# RSA, DSA and ECDSA keys can be loaded from the public/private numbers and/or parameters
rsa_public = RSAPublicKey.from_numbers(
    e=65537,
    n=12.........811
)

rsa_private = RSAPrivateKey.from_numbers(
    e=65537,
    n=12......811,
    d=17......122
)
```

## SSH Certificates
### Attributes
|Attribute|Type|Key|Example Value|Description|
|---|---|---|
|Certificate Type|Integer (1/2)|cert_type|1|The type of certificate, 1 for User and 2 for Host. Can also be defined as sshkey_tools.fields.CERT_TYPE.USER or sshkey_tools.fields.CERT_TYPE.HOST|
|Serial|Integer|serial|11223344|The serial number for the certificate, a 64-bit integer|
|Key ID|String|key_id|someuser@somehost|The key identifier, can be set to any string, for example username, email or other unique identifier|
|Principals|List|principals|['zone-webservers', 'server-01']|The principals for which the certificate is valid, this needs to correspond to the allowed principals on the OpenSSH Server-side. Only valid for User certificates|
|Valid After|Integer|valid_after|datetime.now()|The datetime object or unix timestamp for when the certificate validity starts|
|Valid Before|Integer|valid_before|datetime.now() + timedelta(hours=12)|The datetime object or unix timestamp for when the certificate validity ends|
|Critical Options|Dict|critical_options|{'source-address': '1.2.3.4/8'}|Options set on the certificate that the OpenSSH server cannot choose to ignore (critical). Only valid on user certificates. Valid options are force-command (for limiting the user to a certain shell, e.g. sftp-internal), source-address (to limit the source IPs the user can connect from) and verify-required (to require the user to touch a hardware key before usage)|
|Extensions|Dict/Set/List/Tuple|extensions|{'permit-X11-forwarding', 'permit-port-forwarding'}|Extensions that the certificate holder is allowed to use. Valid options are no-touch-required, permit-X11-forwarding, permit-agent-forwarding, permit-port-forwarding, permit-pty, permit-user-rc|

### Certificate creation
The basis for a certificate is the public key for the subject (User/Host), and bases the format of the certificate on that.
```python
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import (
    serialization as crypto_serialization,
    hashes as crypto_hashes
)
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from sshkey_tools.keys import PublicKey, RSAPrivateKey, RsaAlgs
from sshkey_tools.cert import SSHCertificate
from sshkey_tools.exceptions import SignatureNotPossibleException

user_pubkey = PublicKey.from_file('path/to/user_key.pub')
ca_privkey = PrivateKey.from_file('path/to/ca_key')

# You can create a certificate with a dict of pre-set options
cert_opts = {
    'cert_type': 1,
    'serial': 12345,
    'key_id': "my.user@mycompany.com",
    'principals': [
        'webservers-dev',
        'webservers-prod',
        'servername01'
    ],
    'valid_after': datetime.now(),
    'valid_before': datetime.now() + timedelta(hours=12),
    'critical_options': {},
    'extensions': [
        'permit-pty',
        'permit-user-rc',
        'permit-port-forwarding'
    ]    

}

# Create a signable certificate from a PublicKey class
certificate = SSHCertificate.from_public_class(
    user_pubkey,
    ca_privkey,
    **cert_opts
)

# You can also create the certificate in steps
certificate = SSHCertificate.from_public_class(
    user_pubkey
)

# Set the CA private key used to sign the certificate
certificate.set_ca(ca_privkey)

# Set or update the options one-by-one
for key, value in cert_opts.items():
    certificate.set_opt(key, value)

# Via a dict
certificate.set_opts(**cert_opts)

# Or via parameters
certificate.set_opts(
    cert_type=1,
    serial=12345,
    key_id='my.user@mycompany.com',
    principals=['zone-webservers'],
    valid_after=datetime.now(),
    valid_before=datetime.now() + timedelta(hours=12),
    critical_options={},
    extensions={}
)

# Check if the certificate is ready to be signed
# Will return True or an exception
certificate.can_sign()

# Catch exceptions
try:
    certificate.can_sign()
except SignatureNotPossibleException:
    ...

# Sign the certificate
certificate.sign()

# For RSA, you can choose the hashing algorithm used for creating
# the hash of the certificate data before signing
certificate.sign(
    hash_alg=RsaAlgs.SHA512
)

# If you want to verify the signature after creation, 
# you can do so with the verify()-method
#
# Please note that a public key should always be provided
# to this function if the certificate was not just created,
# since an attacker very well could have replaced CA public key
# and signature with their own
#
# The method will return None if successful, and InvalidSignatureException
# if the signature does not match the data
certificate.verify()
certificate.verify(ca_privkey.public_key)


# If you prefer to verify manually, you can use the CA public key object
# from sshkey_tools or the key object from pyca/cryptography

# PublicKey
ca_pubkey = PublicKey.from_file('path/to/ca_pubkey')


ca_pubkey.verify(
    certificate.get_signable_data(),
    certificate.signature.value,
    RsaAlgs.SHA256.value[1]
)

# pyca/cryptography RSAPrivateKey
with open('path/to/ca_pubkey', 'rb') as file:
    crypto_ca_pubkey = crypto_serialization.load_ssh_public_key(file.read())

crypto_ca_pubkey.verify(
    certificate.get_signable_data(),
    certificate.signature.value,
    crypto_padding.PKCS1v15(),
    crypto_hashes.SHA256()
)

# You now have an OpenSSH Certificate
# Export it to file, string or bytes
certificate.to_file('path/to/user_key-cert.pub')
cert_string = certificate.to_string()
cert_bytes = certificate.to_bytes()
```

### Load an existing certificate
Certificates can be loaded from file, a string/bytestring with file contents
or the base64-decoded byte data of the certificate

```python
from sshkey_tools.keys import PublicKey, PrivateKey
from sshkey_tools.cert import SSHCertificate, RSACertificate

# Load an existing certificate
certificate = SSHCertificate.from_file('path/to/user_key-cert.pub')

# or
certificate = RSACertificate.from_file('path/to/user_key-cert.pub')

# Verify the certificate with a CA public key
ca_pubkey = PublicKey.from_file('path/to/ca_key.pub')
certificate.verify(ca_pubkey)

# Create a new certificate with duplicate values from existing certificate
# You can use existing or previously issued certificates as templates
# for creating new ones
certificate = SSHCertificate.from_file('path/to/user_key-cert.pub')
ca_privkey = PrivateKey.from_file('path/to/ca_privkey')

certificate.set_ca(ca_privkey)
certificate.sign()
certificate.to_file('path/to/user_key-cert2.pub')
```