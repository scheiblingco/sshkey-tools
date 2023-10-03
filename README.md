![SSHKey Tools](./assets/sshkey-tools-plain.svg)
# sshkey-tools
[![PyPI version](https://badge.fury.io/py/sshkey-tools.svg)](https://badge.fury.io/py/sshkey-tools)
![Linting](https://github.com/scheiblingco/sshkey-tools/actions/workflows/linting.yml/badge.svg)
![Testing-Dev](https://github.com/scheiblingco/sshkey-tools/actions/workflows/dev_testing.yml/badge.svg)
![Testing-Build](https://github.com/scheiblingco/sshkey-tools/actions/workflows/deploy_testing.yml/badge.svg)
![Build](https://github.com/scheiblingco/sshkey-tools/actions/workflows/publish.yml/badge.svg)
[![CodeQL](https://github.com/scheiblingco/sshkey-tools/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/scheiblingco/sshkey-tools/actions/workflows/github-code-scanning/codeql)



Python package for managing OpenSSH keypairs and certificates ([protocol.CERTKEYS](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys)). Supported functionality includes:

## Notice
The DSA algorithm has been deprecated and is removed in pyca/cryptography 41.x, meaning **version 0.9.* of this package will be the last to support DSA keys and certificates** for SSH. If there is any demand to reintroduce DSA support, please open an issue regarding this and we'll look into it. 

For now, **0.9.* will be restricted to version <41.1 of the cryptography package** and **0.10 will have its DSA support removed**. We've introduced a deprecation notice in version 0.9.3.

### Background
The DSA algorithm is considered deprecated and will be removed in a future version. If possible, use RSA, [(ECDSA)](https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a) or ED25519 as a first-hand choice.

### Notice from OpenSSH:
```
OpenSSH 7.0 and greater similarly disable the ssh-dss (DSA) public key algorithm. It too is weak and we recommend against its use. It can be re-enabled using the HostKeyAlgorithms configuration option: sshd_config(5) HostKeyAlgorithms
```

[ECDSA has some flaws](https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a), especially when using short nonces or re-using nonces, it can still be used but exercise some caution in regards to nonces/re-signing identical data multiple times.

# Features
### SSH Keys
- Supports RSA, ECDSA and ED25519 keys
- Import existing keys from file, string, byte data or [pyca/cryptography](https://github.com/pyca/cryptography) class
- Generate new keys
- Get public key from private keys
- Sign bytestrings with private keys
- Export to file, string or bytes
- Generate fingerprint

### OpenSSH Certificates
- Supports RSA, ECDSA and ED25519 certificates
- Import existing certificates from file, string or bytes
- Verify certificate signature against internal or separate public key
- Create new certificates from CA private key and subject public key
- Create new certificates using old certificate as template
- Sign certificates
- Export certificates to file, string or bytes

# Roadmap
See issues for planned features and fixes

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
You can find the full documentation at [scheiblingco.github.io/sshkey-tools/](https://scheiblingco.github.io/sshkey-tools/)

## Building the documentation
```bash
pdoc3 src/sshkey_tools/ -o docs --html
cp -rf docs/sshkey_tools/* docs/
rm -rf docs/sshkey_tools
```

## SSH Keypairs (generating, loading, exporting)
```python
# Import the certificate classes
from sshkey_tools.keys import (
    RsaPrivateKey,
    EcdsaPrivateKey,
    Ed25519PrivateKey,
    EcdsaCurves
)
#
## Generating keys
#

# For all keys except ED25519, the key size/curve can be manually specified
# Generate RSA (default is 4096 bits)
rsa_priv = RsaPrivateKey.generate()
rsa_priv = RsaPrivateKey.generate(2048)

# Generate DSA keys (since SSH only supports 1024-bit keys, this is the default)
# DEPRECATED
# dsa_priv = DsaPrivateKey.generate()

# Generate ECDSA keys (The default curve is P521)
ecdsa_priv = EcdsaPrivateKey.generate()
ecdsa_priv = EcdsaPrivateKey.generate(EcdsaCurves.P256)

# Generate ED25519 keys (fixed key size)
ed25519_priv = Ed25519PrivateKey.generate()

#
## Loading keys
#

# Keys can be loaded either via the specific class:
rsa_priv = RsaPrivateKey.from_file("/path/to/key", "OptionalSecurePassword")

# or via the general class, in case the type is not known in advance
rsa_priv = PrivateKey.from_file("/path/to/key", "OptionalSecurePassword")

# The import functions are .from_file(), .from_string() and .from_class() and are valid for both PublicKey and PrivateKey-classes
rsa_priv = PrivateKey.from_string("-----BEGIN OPENSSH PRIVATE KEY...........END -----", "OptionalSecurePassword")
rsa_priv = PrivateKey.from_class(pyca_cryptography_class)

# The different keys can also be loaded from their numbers, e.g. RSA Pubkey:
rsa_priv = PublicKey.from_numbers(65537, 123123123....1)

#
## Key functionality
#

# The public key for any loaded or generated private key is available in the .public_key attribute
ed25519_pub = ed25519_priv.public_key

# The private keys can be exported using to_bytes, to_string or to_file
rsa_priv.to_bytes("OptionalSecurePassword")
rsa_priv.to_string("OptionalSecurePassword", "utf-8")
rsa_priv.to_file("/path/to/file", "OptionalSecurePassword", "utf-8")

# The public keys also have .to_string() and .to_file(), but .to_bytes() is divided into .serialize() and .raw_bytes()
# The comment can be set before export by changing the public_key.comment-attribute
rsa_priv.public_key.comment = "Comment@Comment"

# This will return the serialized public key as found in an OpenSSH keyfile
rsa_priv.public_key.serialize()
b"ssh-rsa AAAA......... Comment@Comment"

# This will return the raw bytes of the key (base64-decoded middle portion)
rsa_priv.public_key.raw_bytes()
b"\0xc\0a\........"
```

## SSH Key Signatures
The loaded private key objects can be used to sign bytestrings, and the public keys can be used to verify signatures on those
```python
from sshkey_tools.keys import RsaPrivateKey, RsaPublicKey
from sshkey_tools.fields import RsaAlgs

signable_data = b'This is a message that will be signed'

privkey = RsaPrivateKey.generate()
pubkey = RsaPrivateKey.public_key

# Sign the data
signature = privkey.sign(signable_data)

# When using an RSA key for the signature, you can specify the hashing algorithm
# The default algorithm is SHA512
signature = privkey.sign(signable_data, RsaAlgs.SHA512)

# Verify the signature (Throws exception if invalid)
pubkey.verify(signable_data, signature)
```

## OpenSSH Certificates
### Introduction
Certificates are a way to handle access management/PAM for OpenSSH with the ability to dynamically grant access during a specific time, to specific servers and/or with specific attributes. There are a couple of upsides to using certificates instead of public/private keys, mainly: 

- Additional Security: Certificate authentication for OpenSSH is built as an extension of public key authentication, enabling additional features on top of key-based access control.
- Short-term access: The user has to request a certificate for their keypair, which together with the private key grants access to the server. Without the certificate the user can't connect to the server - giving you control over how, when and from where the user can connect.
- Hostkey Verification: Certificiates can be issued for the OpenSSH Server, adding the CA public key to the clients enables you to establish servers as trusted without the hostkey warning.
- RBAC: Control which servers or users (principals) a keypair has access to, and specify the required principals for access to certain functionality on the server side.
- Logging: Key ID and Serial fields for tracking of issued certificates
- CRL: Revoke certificates prematurely if they are compromised

### Structure
The original OpenSSH certificate format is a block of parameters, encoded and packed to a bytestring. In this package, the fields have been divided into three parts. For a more detailed information about the format, see [PROTOCOL.certkeys](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys).

### Certificate Header
|Attribute|Type(Length)|Key|Example Value|Description|
|---|---|---|---|---|
|Public Key/Certificate type|string(fixed)|pubkey_type|ssh-rsa-sha2-512-cert-v01@openssh.com|The private key (and certificate) type, derived from the public key for which the certificate is created (Automatically set upon creation)|
|Subject public key|bytestring(variable)|public_key|\x00\x00\x00..........|The public key for which the certificate is created (Automatically set upon creation)|
|Nonce|string|nonce(variable, typically 16 or 32 bytes)|abcdefghijklmnopqrstuvwxyz|A random string included to make attacks that depend on inducing collisions in the signature hash infeasible. (Default is automatically set, can be changed with Certificate.header.nonce = "abcdefg..."|

### Certificate Fields
|Attribute|Type(Length)|Key|Example Value|Description|
|---|---|---|---|---|
|Serial|Integer(64-bit)|serial|1234567890|An optional certificate serial number set by the CA to provide an abbreviated way to refer to certificates from that CA. If a CA does not wish to number its certificates, it must set this field to zero.|
|Certificate type|Integer(1 or 2)|cert_type|1|The type of the certificate, 1 for user certificates, 2 for host certificates|
|Key ID|string(variable)|key_id|someuser@somehost|Free-form text field that is filled in by the CA at the time of signing; the intention is that the contents of this field are used to identify the identity principal in log messages.|
|Valid Principals|List(string(variable))|principals|['some-user', 'some-group', production-webservers']|These principals list the names for which this certificate is valid hostnames for SSH_CERT_TYPE_HOST certificates and usernames for  SH_CERT_TYPE_USER certificates. As a special case, a zero-length "valid principals" field means the certificate is valid for any principal of the specified type.|
|Valid After|Timestamp|valid_after|datetime.now()|Timestamp for the start of the validity period for the certificate|
|Valid Before|Timestamp|valid_before|datetime.now()+timedelta(hours=8) or 1658322031|Timestamp for the end of the validity period for the certificate. Needs to be larger than valid_after, can be a string (ex. 2d, 2w, 1h4m, 99d) or forever (MAX_INT64)|
|Critical Options|Dict(string, string)|critical_options|[]|Zero or more of the available critical options (see below)|
|Extensions|Dict(string, string)/List/Tuple/Set|extensions|[]|Zero or more of the available extensions (see below)|


#### Critical Options
|Name|Format|Description|
|---|---|---|
|force-command|string|Specifies a command that is executed (replacing any the user specified on the ssh command-line) whenever this key is used for authentication.|
|source-address|string|Comma-separated list of source addresses from which this certificate is accepted for authentication. Addresses are specified in CIDR format (nn.nn.nn.nn/nn or hhhh::hhhh/nn). If this option is not present, then certificates may be presented from any source address.|
|verify-required|empty|Flag indicating that signatures made with this certificate must assert FIDO user verification (e.g. PIN or biometric). This option only makes sense for the U2F/FIDO security key types that support this feature in their signature formats.|

#### Extensions
|Name|Format|Description|
|---|---|---|
|no-touch-required|empty|Flag indicating that signatures made with this certificate need not assert FIDO user presence. This option only makes sense for the U2F/FIDO security key types that support this feature in their signature formats.|
|permit-X11-forwarding|empty|Flag indicating that X11 forwarding should be permitted. X11 forwarding will be refused if this option is absent.|
|permit-agent-forwarding|empty|Flag indicating that agent forwarding should be allowed. Agent forwarding must not be permitted unless this option is present.|
|permit-port-forwarding|empty|Flag indicating that port-forwarding should be allowed. If this option is not present, then no port forwarding will be allowed.|
|permit-pty|empty|Flag indicating that PTY allocation should be permitted. In the absence of this option PTY allocation will be disabled.|
|permit-user-rc|empty|Flag indicating that execution of ~/.ssh/rc should be permitted. Execution of this script will not be permitted if this option is not present.|


### Certificate Body
|Attribute|Type(Length)|Key|Example Value|Description|
|---|---|---|---|---|
|Reserved|string(0)|reserved|""|Reserved for future use, must be empty (automatically set upon signing)|
|CA Public Key|bytestring(variable)|ca_pubkey|\x00\x00\x00..........|The public key of the CA that issued this certificate (automatically set upon signing)|
|Signature|bytestring(variable)|signature|\x00\x00\x00..........|The signature of the certificate, created by the CA (automatically set upon signing)|

## Creating, signing and verifying certificates
```python
# Every certificate needs two parts, the subject (user or host) public key and the CA Private key
from sshkey_tools.cert import SSHCertificate, CertificateFields, Ed25519Certificate
from sshkey_tools.keys import Ed25519PrivateKey
from datetime import datetime, timedelta

subject_pubkey = Ed25519PrivateKey.generate().public_key
ca_privkey = Ed25519PrivateKey.generate()

# There are multiple ways to create a certificate, either by creating the certificate body field object first and then creating the certificate, or creating the certificate and setting the fields one by one

# Create certificate body fields
cert_fields = CertificateFields(
    serial=1234567890,
    cert_type=1,
    key_id="someuser@somehost",
    principals=["some-user", "some-group", "production-webservers"],
    valid_after=datetime.now(),
    valid_before=datetime.now() + timedelta(hours=8),
    critical_options=[],
    extensions=[
        "permit-pty",
        "permit-X11-forwarding",
        "permit-agent-forwarding",
    ],
)

# Create certificate from existing fields
certificate = SSHCertificate(
    subject_pubkey=subject_pubkey,
    ca_privkey=ca_privkey,
    fields=cert_fields,
)

# Start with a blank certificate by calling the general class
certificate = SSHCertificate.create(
    subject_pubkey=subject_pubkey,
    ca_privkey=ca_privkey
)

# You can also call the specialized classes directly, for the general class the .create-function needs to be used
certificate = Ed25519Certificate(
    subject_pubkey=subject_pubkey,
    ca_privkey=ca_privkey
)

# Manually set the fields
certificate.fields.serial = 1234567890
certificate.fields.cert_type = 1
certificate.fields.key_id = "someuser@somehost"
certificate.fields.principals = ["some-user", "some-group", "production-webservers"]
certificate.fields.valid_after = datetime.now()
certificate.fields.valid_before = datetime.now() + timedelta(hours=8)
certificate.fields.critical_options = []
certificate.fields.extensions = [
    "allow-pty",
    "permit-X11-forwarding",
    "permit-agent-forwarding",
]

# Check if the certificate is ready to be signed
certificate.can_sign()

# Sign the certificate
certificate.sign()

# Verify the certificate against the included public key (insecure, but useful for testing)
certificate.verify()

# Verify the certificate against a public key that is not included in the certificate
certificate.verify(ca_privkey.public_key)

# Raise an exception if the certificate is invalid
certificate.verify(ca_privkey.public_key, True)

# Export the certificate to file/string
certificate.to_file('filename-cert.pub')
cert_str = certificate.to_string()

```
## Loading, re-creating and verifying existing certificates
```python
from sshkey_tools.cert import SSHCertificate, CertificateFields, Ed25519Certificate
from sshkey_tools.keys import PublicKey, PrivateKey
from datetime import datetime, timedelta

# Load a certificate from file or string
# This will return the correct certificate type based on the contents of the certificate
certificate = SSHCertificate.from_file('filename-cert.pub')
certificate = SSHCertificate.from_string(cert_str)

type(certificate) # sshkey_tools.cert.Ed25519Certificate

# Verify the certificate signature against the included public key (insecure, but useful for testing)
certificate.verify()

# Verify the certificate signature against a public key
pubkey = PublicKey.from_file('filename-pubkey.pub')
certificate.verify(pubkey)

# Raise an exception if the certificate is invalid
certificate.verify(pubkey, True)

# Use the loaded certificate as a template to create a new one
new_ca = PrivateKey.from_file('filename-ca')
certificate.replace_ca(new_ca)
certificate.sign()

```

## Changelog
### 0.9.1
- Updated documentation
- Fix for bug where exception would occur when trying to export a key without a comment set

### 0.9
- Adjustments to certificate field handling for easier usage/syntax autocompletion
- Updated testing
- Removed method for changing RSA hash method (now default SHA512)

### 0.8.2
- Fixed bug where an RSA certificate would send the RSA alg to the sign() function of another key type

### 0.8.1
- Changed versioning for out-of-github installation/packaging
- Moved documentation to HTML (PDOC3)
- Added verification of certificate signature
- Added option to choose RSA hashing algorithm for signing
- Removed test files
- Added documentation deployment CD for GH pages

### 0.8
- Initial public release
