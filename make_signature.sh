#!/bin/bash
ssh-keygen -t rsa -b 4096 -f testkeys/id_rsa -N ''
ssh-keygen -t ecdsa -f testkeys/id_ecdsa -N ''
ssh-keygen -t ed25519 -f testkeys/id_ed25519 -N ''
echo "Hello World" | tee testkeys/rsa.txt | tee testkeys/ecdsa.txt | tee testkeys/ed25519.txt

ssh-keygen -Y sign -n hello@world -f testkeys/id_rsa testkeys/rsa.txt
ssh-keygen -Y sign -n hello@world -f testkeys/id_ecdsa testkeys/ecdsa.txt
ssh-keygen -Y sign -n hello@world -f testkeys/id_ed25519 testkeys/ed25519.txt