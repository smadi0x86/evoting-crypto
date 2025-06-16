#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>

/*
    cc rsa-keygen.c -o rsa-keygen -lgmp

    https://gmplib.org/manual/Initializing-Integers
*/

#define BIT_LENGTH 1024

void generatePrime(mpz_t prime, gmp_randstate_t state, int bits) {
    // https://gmplib.org/manual/Integer-Random-Numbers
    mpz_rrandomb(prime, state, bits);
    mpz_nextprime(prime, prime);
}

int main() {
    mpz_t p, q, n, e;

    // https://gmplib.org/manual/Random-State-Initialization
    gmp_randstate_t state;

    mpz_inits(p, q, n, e, NULL);
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));

    // https://gmplib.org/manual/Number-Theoretic-Functions
    generatePrime(p, state, BIT_LENGTH);
    generatePrime(q, state, BIT_LENGTH);

    mpz_mul(n, p, q);

    mpz_set_ui(e, 65537);

    FILE *fp = fopen("rsa_keys.txt", "w");
    if (!fp) {
        perror("Error opening file");

	return EXIT_FAILURE;
    }

    gmp_fprintf(fp, "p = %Zd\n", p);
    gmp_fprintf(fp, "q = %Zd\n", q);
    gmp_fprintf(fp, "e = %Zd\n", e);

    fclose(fp);
    printf("p, q and e values written to rsa_keys.txt\n");

    mpz_clears(p, q, n, e, NULL);
    gmp_randclear(state);

    return EXIT_SUCCESS;
}