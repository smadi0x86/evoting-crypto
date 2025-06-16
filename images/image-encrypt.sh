#!/bin/bash

mkdir -p bin

gcc -Wall -Wextra -o bin/encryptImage \
    src/encryptImage.c \
    src/des.c \
    src/desModes.c \
    src/utils.c

if [ $? -eq 0 ]; then
    echo "Build successful! You can run the BMP encryption demo with: bin/encryptImage <bmp_file>"
else
    echo "Build failed."
fi