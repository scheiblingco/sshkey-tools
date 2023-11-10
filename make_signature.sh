#!/bin/bash
ssh-keygen -t rsa -b 4096 -f id_rsa -N ''
ssh-keygen -t ecdsa -f id_ecdsa -N ''
ssh-keygen -t ed25519 -f id_ed25519 -N ''
echo "Hello World" | tee rsa.txt | tee ecdsa.txt | tee ed25519.txt

ssh-keygen -Y sign -n hello@world -f id_rsa rsa.txt
ssh-keygen -Y sign -n hello@world -f id_ecdsa ecdsa.txt
ssh-keygen -Y sign -n hello@world -f id_ed25519 ed25519.txt