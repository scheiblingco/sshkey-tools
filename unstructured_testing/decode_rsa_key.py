# pylint: disable-all
import os
import random
from time import time
from base64 import b64encode, b64decode
from paramiko.message import Message
from paramiko.ecdsakey import ECDSAKey

with open('testcerts/rsa_user-cert.pub') as f:
    cont = f.read().split(' ')[1]
    cert = Message(b64decode(cont))
  
# Certificate type
print(" \nCertificate type:")
print(cert.get_string())

# Nonce
print(' \nNonce:')
print(cert.get_string())

# E
print(' \nE:')
print(cert.get_mpint())

# N
print(' \nN:')
print(cert.get_mpint())

# Serial
print(' \nSerial:')
print(cert.get_int64())

# Type
print(' \nType:')
print(cert.get_int())

# Key ID 
print(' \nKey ID:')
print(cert.get_string())

# Principals
print(' \nPrincipals:')
print(cert.get_list())

# Valid after
print(' \nValid after:')
print(cert.get_int64())

# Valid before
print(' \nValid before:')
print(cert.get_int64())

# Critical options
print(' \nCritical options:')
print(cert.get_list())

# Extensions
print(' \nExtensions:')
print(cert.get_list())

# Reserved
print(' \nReserved:')
print(cert.get_string())

# Signer public key
print(' \nSigner public key:')
print(cert.get_string())

# Signature
print(' \nSignature:')
print(cert.get_string())