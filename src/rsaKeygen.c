#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include "rsaKeygen.h"
#include "rsa.h"

// https://crypto.stanford.edu/pbc/notes/numbertheory/millerrabin.html
void generatePrime(mpz_t prime, unsigned int bits, gmp_randstate_t state) {

    mpz_t tmp;
    mpz_init(tmp);

    do {
        // Generate a random number between 0 and 2^bits - 1
        mpz_urandomb(prime, state, bits);

        // Set the high bit to ensure full bit length
        mpz_setbit(prime, bits - 1);

        // Set the low bit to ensure it's odd (even numbers aren't prime except for 2)
        mpz_setbit(prime, 0);

        // Check if the number is prime, while not prime, try again
        // https://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    } while (mpz_probab_prime_p(prime, 40) < 1); // 40 Miller-Rabin iterations

    mpz_clear(tmp);
}

int rsagenkeypairRandom(rsakeyPair *keyPair, unsigned int pBits,
                               unsigned int qBits, unsigned long e_val) {

    // https://gmplib.org/manual/Random-Number-Functions
    gmp_randstate_t randomState;

    gmp_randinit_mt(randomState);
    gmp_randseed_ui(randomState, time(NULL));

    // get a random p and q
    generatePrime(keyPair->p, pBits, randomState);
    generatePrime(keyPair->q, qBits, randomState);

    // check p != q, if they are equal, generate a new q
    while (mpz_cmp(keyPair->p, keyPair->q) == 0) {

        generatePrime(keyPair->q, qBits, randomState);
    }

    // n = p * q
    mpz_mul(keyPair->n, keyPair->p, keyPair->q);

    // phi(n) = (p-1) * (q-1)
    mpz_t pMinus1, qMinus1;

    mpz_init(pMinus1);
    mpz_init(qMinus1);

    mpz_sub_ui(pMinus1, keyPair->p, 1);
    mpz_sub_ui(qMinus1, keyPair->q, 1);
    mpz_mul(keyPair->phi, pMinus1, qMinus1);

    // set public exponent e
    mpz_set_ui(keyPair->e, e_val);

    // check if 1 < e < phi(n) and gcd(e, phi(n)) = 1
    if (mpz_cmp_ui(keyPair->e, 1) <= 0 || mpz_cmp(keyPair->e, keyPair->phi) >= 0) {
        fprintf(stderr, "e must be in range 1 < e < phi(n)\n");

        mpz_clear(pMinus1);
        mpz_clear(qMinus1);
        gmp_randclear(randomState);

        return EXIT_FAILURE;
    }

    mpz_t gcdValue;

    mpz_init(gcdValue);

    mpz_gcd(gcdValue, keyPair->e, keyPair->phi);

    if (mpz_cmp_ui(gcdValue, 1) != 0) {
        fprintf(stderr, "e must be coprime to phi(n)\n");

        mpz_clear(pMinus1);
        mpz_clear(qMinus1);
        mpz_clear(gcdValue);
        gmp_randclear(randomState);

        return EXIT_FAILURE;
    }

    if (!mpz_invert(keyPair->d, keyPair->e, keyPair->phi)) {
        fprintf(stderr, "Failed to calculate modular inverse\n");

        mpz_clear(pMinus1);
        mpz_clear(qMinus1);
        mpz_clear(gcdValue);
        gmp_randclear(randomState);

        return EXIT_FAILURE;
    }

    mpz_clear(pMinus1);
    mpz_clear(qMinus1);
    mpz_clear(gcdValue);
    gmp_randclear(randomState);

    return EXIT_SUCCESS;
}

int rsagenKey(rsakeyPair *keyPair, unsigned int keyBits) {

    if (keyBits < 1024) {
        fprintf(stderr, "Key size less than 1024 bits, this is not secure\n");
    }

    // make sure p and q size are close to each other for security
    // for example keybits = n = 1024, so 1024 / 2 = 512 bits for p and q
    unsigned int pBits = keyBits / 2;
    unsigned int qBits = keyBits - pBits;

    return rsagenkeypairRandom(keyPair, pBits, qBits, 65537);
}