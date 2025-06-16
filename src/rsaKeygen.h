#ifndef RSA_KEYGEN_H
#define RSA_KEYGEN_H

#include <gmp.h>
#include <stdint.h>
#include "rsa.h"

void generatePrime(mpz_t prime, unsigned int bits, gmp_randstate_t state);

int rsagenkeypairRandom(rsakeyPair *keyPair, unsigned int pBits,
                                unsigned int qBits, unsigned long e_val);

int rsagenKey(rsakeyPair *keyPair, unsigned int keyBits);

#endif