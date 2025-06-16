#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

uint64_t permute(uint64_t input, const uint8_t *table, int outputLength, int inputLength);
uint32_t circularrotateleftBy28(uint32_t value, int bits);
uint64_t bytestoUint64(const uint8_t *bytes);
void uint64toBytes(uint64_t value, uint8_t *bytes);
void printHex(const uint8_t *data, size_t len);
void getInput(const char* prompt, char* buffer, size_t buffer_size);
void genrandomdesKey(uint8_t *key);
void genrandomIV(uint8_t *iv);
int hextoBytes(const char *hex_str, uint8_t *bytes, size_t bytesLength);
void pkcs7Padding(uint8_t *out, const uint8_t *in, size_t length, size_t blocksize);

#endif