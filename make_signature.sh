#!/bin/bash
ssh-keygen -t rsa -b 4096 -f id_rsa -N ''
echo "Hello World" > hello.txt
ssh-keygen -Y sign -n hello@world -f id_rsa hello.txt