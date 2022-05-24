# sshkey-tools (Work in progress)

> Auto-generated documentation index.

Python and CLI tools for managing OpenSSH keypairs and certificates

Full Sshkey-tools project documentation can be found in [Modules](MODULES.md#sshkey-tools-modules)

- [sshkey-tools (Work in progress)](#sshkey-tools-work-in-progress)
- [key is an instance of PrivateKey or any of its subclasses](#key-is-an-instance-of-privatekey-or-any-of-its-subclasses)
    - [Existing certificates](#existing-certificates)
    - [New certificates](#new-certificates)
        - [Specific certificate classes](#specific-certificate-classes)
  - [Sshkey-tools Modules](MODULES.md#sshkey-tools-modules)

# Usage
sshkey --help

# Table of Contents
- [sshkey-tools (Work in progress)](#sshkey-tools--work-in-progress-)
- [Usage](#usage)
- [Python Usage](#python-usage)
  * [Private keys](#private-keys)
    + [Generalized class](#generalized-class)
    + [Specific key classes](#specific-key-classes)
  * [Public Keys](#public-keys)
    + [Generalized class](#generalized-class-1)
    + [Specific key classes](#specific-key-classes-1)
  * [Certificates](#certificates)

# Python Usage
## Private keys
### Generalized class
```python
from sshkey_tools.keys import PrivateKey

# Load from keyfile (Returns sshkey_tools.keys.RSAPrivateKey, etc.)
key = PrivateKey.from_file('id_rsa')

# Load from string/file contents (Returns sshkey_tools.keys.RSAPrivateKey for RSA, etc.)
key = PrivateKey.from_string('-----Begin.......... End-----')

# Load from key bytes (inner bytes, without comment and key type prefix)
key = PrivateKey.from_bytes(b'%x00%x00......')

# If the key is password protected, set the password variable
key = PrivateKey.from_...('', password='abc123')

```

### Specific key classes
In addition to specifically loading e.g. an RSA key with the from_bytes, from_string or from_file methods above, you can also specifically load a key type with that function with e.g. RSAPrivateKey.from_file('filename')
```python
from sshkey_tools.keys import (
    RSAPrivateKey,
    DSAPrivateKey,
    ECDSAPrivateKey,
    ED25519PrivateKey
)

# Generate new RSA key
key = RSAPrivateKey.generate(
    key_size=4096,
    public_exponent=65537
)

# Generate new DSA/DSS key
key = DSAPrivateKey.generate(
    key_size=4096,
)

# Generate new ECDSA key
key = ECDSAPrivateKey.generate(
    curve=ECDSA_CURVES.SECP384R1()
)

# Generate new ED25519 key
key = ED25519PrivateKey.generate()

# Load RSA key from numbers
key = RSAPrivateKey.from_numbers(
    n=123123,
    e=123123,
    p=123123,
    q=123123,
    d=123123
)

# Load DSA key from numbers
key = DSAPrivateKey.from_numbers(
    p=123123,
    q=123123,
    g=123123,
    y=123123,
    x=123123
)

# Load ECDSA key from numbers
key = ECDSAPrivateKey.from_numbers(
    private_number=123123,
    x=123123,
    y=123123,
    curve=ECDSA_CURVES.SECP384R1()
)

# ED25519 keys don't support loading from numbers
```

### Exporting private keys
The export class looks the same on all the PrivateKey-classes, the example below will use the general PrivateKey class but everything works the same for the specific classes

```python
from sshkey_tools.keys import FORMAT

# key is an instance of PrivateKey or any of its subclasses

key_str = key.to_string(FORMAT.OpenSSH)
print(key_str)
"""
-----BEGIN OPENSSH PRIVATE KEY-----
ABCDEFG.......
-----END OPENSSH PRIVATE KEY-----
"""

# Produces the same output as above, but writes it directly to file
key.to_file('samplekey', FORMAT.OpenSSH)

key_bin = key.to_bytes(FORMAT.BARE)
print(key_bin)
b"""
%x0f%x00%x12.......
"""
```

## Public Keys
### Generalized class
```python
from sshkey_tools.keys import PrivateKey, PublicKey

# Load from keyfile (Returns sshkey_tools.keys.RSAPrivateKey, etc.)
public_key = PublicKey.from_file('id_rsa.pub')

# Load from string/file contents (Returns sshkey_tools.keys.RSAPublicKey for RSA, etc.)
public_key = PublicKey.from_string('ssh-rsa AA.......... someone@somehost')

# Load from key bytes (inner bytes, without comment and key type prefix)
public_key = PublicKey.from_bytes(b'%x00%x00......')

# Load public key from private key class 
private_key = PrivateKey.from_file('id_rsa')
public_key = private_key.public_key()

```

### Specific key classes
In addition to specifically loading e.g. an RSA key with the from_bytes, from_string or from_file methods above, you can also specifically load a key type with that function with e.g. RSAPrivateKey.from_file('filename')
```python
from sshkey_tools.keys import (
    RSAPublicKey,
    DSAPublicKey,
    ECDSAPublicKey,
    ED25519PublicKey
)

# Load RSA public key from numbers
key = RSAPublicKey.from_numbers(
    n=123123,
    e=123123
)

# Load DSA public key from numbers
key = DSAPublicKey.from_numbers(
    p=123123,
    q=123123,
    g=123123,
    y=123123
)

# Load ECDSA public key from numbers
key = ECDSAPublicKey.from_numbers(
    x=123123,
    y=123123,
    curve=ECDSA_CURVES.SECP384R1()
)

# ED25519 keys don't support loading from numbers
```
### Exporting public keys
```python
# pubkey can be an instance of any of the PublicKeyClass children

```

## Certificates
### Generalized classes
```python
from sshkey_tools.cert import SSHCertificate

## Existing certificates

# Load from file (Returns specific class, e.g. sshkey_tools.cert.RSACertificate)
certificate = SSHCertificate.from_file('id_rsa-cert.pub')

# Load from string/file contents
certificate = SSHCertificate.from_string('ssh-rsa-cert-v01@openssh.com AA.......... someone@somehost')

# Load from key bytes (inner bytes, without comment and type prefix)
certificate = SSHCertificate.from_bytes(b'%x00%x00.......')

## New certificates

# Create a blank certificate for a specific public key, automatically returns the right certificate class
certificate = SSHCertificate.from_public(PublicKeyClass pubkey)

# Create a certificate from a dictionary with values
# The only mandatory value at this stage is the public_key that is to be signed
cert_val = {
    "serial": "abcdef",
    "key_id": 123123,
    "public_key": pubkey
}
```

certificate = SSHCertificate.from_dict(cert_val)

### Specific certificate classes

```python
from sshkey_tools.cert import (
    RSACertificate,
    DSACertificate,
    ECDSACertificate,
    ED25519Certificate
)

```

### The signing process
The signing process consists of three main steps

1. Create a certificate object for a public key
2. Add attributes
3. Sign the certificate with your CA

#### Create a certificate for a public key
```python
from sshkey_tools.keys import PublicKey, PrivateKey
from sshkey_tools.cert import SSHCertificate

# Load the client public key and the CA private key
client_pubkey = PublicKey.from_file('client.pub')
ca_privkey = PrivateKey.from_file('ca_key')

# Create a blank certificate object from the client public key
# The certificate type is defined by the client key, not the CA
certificate = SSHCertificate.from_public(client_pubkey)

# Add the required attributes to the key
# All attributes can be set either by set_[name](value) or via the set_array function
certificate.set_type(USER)
certificate.set_array(
    "serial": "abc123",
    "key_id": 123,
    "principals": [
        'webservers',
        'database'
    ]
    .....
)

# Once done, make sure the certificate has all the required attributes
# Then, feed the CA Private key to the sign function
if certificate.can_sign():
    certificate.sign(ca_privkey)

# You can check if the certificate has been successfully signed with the is_signature_valid() function
# Then, export the certificate to file, string or bytes
if certificate.is_signature_valid():
    # If no filename is provided, the certificate is saved as [user_pubkey_name]-cert.pub
    certificate.to_file('id_rsa-cert.pub')
    cert_string = certificate.to_string()
    cert_bytes = certificate.to_bytes()

```

# TODO
- PrivateKey.to_file/string/bytes
- PublicKey.to_file/string/bytes
- Certificate.to_file/string/bytes
- Exceptions.py
