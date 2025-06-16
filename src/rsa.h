#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

/*
    sudo apt install libgmp-dev

    https://gmplib.org/manual/Nomenclature-and-Types
*/

typedef struct {
    mpz_t n;
    mpz_t e;
    mpz_t d;
    mpz_t p;
    mpz_t q;
    mpz_t phi;
} rsakeyPair;

void rsainitkeyPair(rsakeyPair *keyPair);

void rsaclearkeyPair(rsakeyPair *keyPair);

int rsagenkeyPair(rsakeyPair *keyPair, const char *p_str, const char *q_str, const char *e_str);

int rsaEncrypt(const rsakeyPair *keyPair, const unsigned char *message, size_t messageLen,
                mpz_t *encrypted);

int rsaDecrypt(const rsakeyPair *keyPair, const mpz_t encrypted, unsigned char **decrypted,
                size_t *decryptedLen);

int rsaSign(const rsakeyPair *keyPair, const unsigned char *hash, size_t hashLength,
             mpz_t *signature);

int rsaVerify(const rsakeyPair *keyPair, const unsigned char *hash, size_t hashLength,
               const mpz_t signature);

int isPrime(const char *numStr);
void printrsakeyInfo(const rsakeyPair *keyPair);

#endif