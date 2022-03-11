# sshkey-tools
Tools for managing OpenSSH keypairs and certificates


# Notes
- https://gist.github.com/thomdixon/bc3d664b6305adec9ecbc155b5ca3b6d
- https://stackoverflow.com/questions/59243185/generating-elliptic-curve-private-key-in-python-with-the-cryptography-library
- https://dev.to/aaronktberry/generating-encrypted-key-pairs-in-python-69b
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
- 


# Get actual pubkey from file
```python
decode_string = lambda x: unpack('>I', x[:4])[0]+4

with open('ssh_user.pub', 'r') as f:
    pub_data = f.read()

_, bin = bin[4:stsz(bin)], bin[stsz(bin):]
_, bin = bin[4:stsz(bin)], bin[stsz(bin):]
pubkey, bin = bin[4:stsz(bin)], bin[stsz(bin):]
```

