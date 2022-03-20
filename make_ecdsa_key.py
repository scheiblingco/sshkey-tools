import os, math, random
from time import time
from base64 import b64encode, b64decode
from paramiko.message import Message
from paramiko.ecdsakey import ECDSAKey

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from src.sshkey_tools import helpers as func

# Create the initial object
made = b''
para = Message()

# Load the user certificate to check for types
with open('ssh_user.pub', 'r') as f:
    user_pubkey = f.read().split(' ')[1]
    user_pubkey = Message(b64decode(user_pubkey))
    key_type = user_pubkey.get_string()
    key_curve = user_pubkey.get_string()
    user_pubkey = user_pubkey.get_string()
    
# Add certificate type
made += func.encode_string(b'{key_type}-cert-v01@openssh.com')
para.add_string(b'{key_type}-cert-v01@openssh.com')

