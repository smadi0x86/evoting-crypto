#!/bin/bash

mkdir -p bin

gcc -Wall -Wextra -o bin/rsashortAttack \
    src/rsashortAttack.c \
    src/rsa.c \
    src/rsaKeygen.c \
    src/utils.c \
    -lgmp -lm

if [ $? -eq 0 ]; then
    echo "Build successful! You can run the RSA security assessment with: bin/rsashortAttack"
else
    echo "Build failed."
fi