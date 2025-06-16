#include <time.h>
#include <assert.h>
#include "utils.h"
#include "rsa.h"

// @smadi0x86

// rsa key pair struct (https://gmplib.org/manual/Initializing-Integers)
void rsainitkeyPair(rsakeyPair *keyPair) {
    // n = p*q
    mpz_init(keyPair->n);
    // e
    mpz_init(keyPair->e);
    // d = e^-1 mod phi(n)
    mpz_init(keyPair->d);
    // p, q primes
    mpz_init(keyPair->p);
    mpz_init(keyPair->q);
    // phi(n) = (p-1)*(q-1)
    mpz_init(keyPair->phi);
}

void rsaclearkeyPair(rsakeyPair *keyPair) {
    mpz_clear(keyPair->n);
    mpz_clear(keyPair->e);
    mpz_clear(keyPair->d);
    mpz_clear(keyPair->p);
    mpz_clear(keyPair->q);
    mpz_clear(keyPair->phi);
}

int isPrime(const char *numStr) {
    mpz_t num;

    mpz_init(num);

    mpz_set_str(num, numStr, 10);

    // 40 miller rabbin iteration, https://gmplib.org/manual/Number-Theoretic-Functions
    int result = mpz_probab_prime_p(num, 40);

    mpz_clear(num);

    // 2 = definitely prime, 1 = probably prime, 0 = composite
    // i dont care about probably as its fast and the chance of it being composite is near 0
    return result > 0;
}

// calc modular multiplicative inverse
// d = e^-1 mod phi
static int modInverse(mpz_t result, const mpz_t e, const mpz_t phi) {
    // check if gcd(e, phi) = 1 (e and phi are coprime)
    mpz_t gcdValue;

    // allocate memory for gcdValue and set it to 0
    mpz_init(gcdValue);

    // calc gcd(e, phi)
    mpz_gcd(gcdValue, e, phi);

    // check if e and phi are coprime
    if (mpz_cmp_ui(gcdValue, 1) != 0) {

        mpz_clear(gcdValue);

        return EXIT_FAILURE;
    }

    mpz_clear(gcdValue);

    // compute inverse of e mod phi and store in result
    mpz_invert(result, e, phi);

    return EXIT_SUCCESS;
}

int rsagenkeyPair(rsakeyPair *keyPair, const char *p_str, const char *q_str, const char *e_str) {

    // check p and q are primes
    if (!isPrime(p_str) || !isPrime(q_str)) {
        fprintf(stderr, "p or q are not prime\n");

        return EXIT_FAILURE;
    }

    // set p and q from strings as base 10 (decimal)
    mpz_set_str(keyPair->p, p_str, 10);
    mpz_set_str(keyPair->q, q_str, 10);

    // calc n = p * q
    mpz_mul(keyPair->n, keyPair->p, keyPair->q);

    // calc euler, phi(n) = (p-1) * (q-1)
    mpz_t pMinus1, qMinus1;

    mpz_init(pMinus1);
    mpz_init(qMinus1);

    mpz_sub_ui(pMinus1, keyPair->p, 1);
    mpz_sub_ui(qMinus1, keyPair->q, 1);

    mpz_mul(keyPair->phi, pMinus1, qMinus1);

    // now we set public exponent (e) as base 10 (decimal)
    mpz_set_str(keyPair->e, e_str, 10);

    // check if 1 < e < phi(n) and gcd(e, phi(n)) = 1
    if (mpz_cmp_ui(keyPair->e, 1) <= 0 || mpz_cmp(keyPair->e, keyPair->phi) >= 0) {
        fprintf(stderr, "e must be in range 1 < e < phi(n)\n");
        // just clear
        mpz_clear(pMinus1);
        mpz_clear(qMinus1);

        return EXIT_FAILURE;
    }

    mpz_t gcdValue;

    mpz_init(gcdValue);

    // get gcd of e and phi(n)
    mpz_gcd(gcdValue, keyPair->e, keyPair->phi);

    // check if e and phi(n) are coprime
    if (mpz_cmp_ui(gcdValue, 1) != 0) {
        fprintf(stderr, "e must be coprime to phi(n)\n");

        // clear memory
        mpz_clear(pMinus1);
        mpz_clear(qMinus1);
        mpz_clear(gcdValue);

        return EXIT_FAILURE;
    }

    // now we calc private key (d), d = e^-1 mod phi(n)
    // if modInverse fails, we can't calc d
    if (!modInverse(keyPair->d, keyPair->e, keyPair->phi)) {
        fprintf(stderr, "Failed to calculate modular inverse\n");

        mpz_clear(pMinus1);
        mpz_clear(qMinus1);
        mpz_clear(gcdValue);

        return EXIT_FAILURE;
    }

    // everything went well, just clear memory
    mpz_clear(pMinus1);
    mpz_clear(qMinus1);
    mpz_clear(gcdValue);

    return EXIT_SUCCESS;
}

// c = m^e mod n
int rsaEncrypt(const rsakeyPair *keyPair, const unsigned char *message, size_t messageLen,
                mpz_t *encrypted) {

    mpz_t m;

    mpz_init(m);

    // https://gmplib.org/manual/Importing-and-Exporting
    // import message into m, messageLen bytes to import, 1 as single block, 1 each block 1 byte, 1 for big endian and 0 for no padding
    mpz_import(m, messageLen, 1, 1, 1, 0, message);

    // we need to check that m < n
    if (mpz_cmp(m, keyPair->n) >= 0) {
        fprintf(stderr, "Message is too large for the given key\n");

        mpz_clear(m);

        return EXIT_FAILURE;
    }

    // init our encrypted message
    mpz_init(*encrypted);

    // square and multiply c = m^e mod n
    mpz_powm(*encrypted, m, keyPair->e, keyPair->n);

    mpz_clear(m);

    return EXIT_SUCCESS;
}

// m = c^d mod n
int rsaDecrypt(const rsakeyPair *keyPair, const mpz_t encrypted, unsigned char **decrypted,
                size_t *decryptedLen) {

    // first check that encrypted < n
    if (mpz_cmp(encrypted, keyPair->n) >= 0) {
        fprintf(stderr, "Encrypted message is too large for the given key\n");

        return EXIT_FAILURE;
    }

    // Compute m = c^d mod n
    mpz_t m;
    mpz_init(m);

    mpz_powm(m, encrypted, keyPair->d, keyPair->n);

    // get size of decrypted msg and store in bufferSize
    // (m,2) + 7) / 8, get num of bytes needed to store m in binary
    size_t bufferSize = (mpz_sizeinbase(m, 2) + 7) / 8;

    // allocate memory for the decrypted msg
    *decrypted = (unsigned char *)malloc(bufferSize);

    if (*decrypted == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        mpz_clear(m);

        return EXIT_FAILURE;
    }

    // hold num of bytes
    size_t count;

    // export m to decrypted buffer as a big-endian word
    mpz_export(*decrypted, &count, 1, 1, 1, 0, m);

    // now count is stored in the value of decryptedLen
    *decryptedLen = count;

    mpz_clear(m);

    return EXIT_SUCCESS;
}

// signedMessage = hash^d mod n
int rsaSign(const rsakeyPair *keyPair, const unsigned char *hash, size_t hashLength,
             mpz_t *signature) {

    mpz_t h;

    mpz_init(h);

    // store result in h, hash length bytes to import, 1 as single block, 1 each block 1 byte, 1 for big endian and 0 for no padding
    // big endian is used for compatibility with SHA-256 output
    mpz_import(h, hashLength, 1, 1, 1, 0, hash);

    // IMPORTANT: Check that h < n
    if (mpz_cmp(h, keyPair->n) >= 0) {
        fprintf(stderr, "SHA-256 hash is too large for the given key (n = p x q) %s\n", mpz_get_str(NULL, 10, keyPair->n));

        mpz_clear(h);

        return EXIT_FAILURE;
    }

    mpz_init(*signature);

    // square and multiply, signature = h^d mod n
    mpz_powm(*signature, h, keyPair->d, keyPair->n);

    mpz_clear(h);

    return EXIT_SUCCESS;
}

int rsaVerify(const rsakeyPair *keyPair, const unsigned char *hash, size_t hashLength,
               const mpz_t signature) {

    // check signature < n
    if (mpz_cmp(signature, keyPair->n) >= 0) {
        fprintf(stderr, "Signature is too large for the given key\n");

        return EXIT_FAILURE;
    }

    // calc h' = signature^e mod n
    mpz_t hashPrime;

    mpz_init(hashPrime);
    mpz_powm(hashPrime, signature, keyPair->e, keyPair->n);

    // original hash
    mpz_t h;

    mpz_init(h);

    mpz_import(h, hashLength, 1, 1, 1, 0, hash);

    // compare h' and h
    // if they are equal, the signature is valid
    int result = (mpz_cmp(h, hashPrime) == 0);

    mpz_clear(h);
    mpz_clear(hashPrime);

    return result;
}

void printrsakeyInfo(const rsakeyPair *keyPair) {
    char *n_str = NULL;
    char *e_str = NULL;
    char *d_str = NULL;
    char *p_str = NULL;
    char *q_str = NULL;

    // change to strings for printing (https://gmplib.org/manual/Converting-Integers-to-Strings)
    n_str = mpz_get_str(NULL, 10, keyPair->n);
    e_str = mpz_get_str(NULL, 10, keyPair->e);
    d_str = mpz_get_str(NULL, 10, keyPair->d);
    p_str = mpz_get_str(NULL, 10, keyPair->p);
    q_str = mpz_get_str(NULL, 10, keyPair->q);

    // get space required for n in bits
    size_t n_bits = mpz_sizeinbase(keyPair->n, 2);

    printf("RSA Key Information:\n");
    printf("----------------------\n");
    printf("Key Size: %zu bits\n", n_bits);
    printf("p: %s\n", p_str);
    printf("q: %s\n", q_str);
    printf("n (modulus): %s\n", n_str);
    printf("e (public exponent): %s\n", e_str);
    printf("d (private exponent): %s\n", d_str);

    free(n_str);
    free(e_str);
    free(d_str);
    free(p_str);
    free(q_str);
}