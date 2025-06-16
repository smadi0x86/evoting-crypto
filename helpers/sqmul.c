#include <stdio.h>
#include <stdlib.h>

/*

 * cc sqmul.c -o sqmul

 * In our evoting system and rsa short message attack we are using mpz_powm() function from gmp library
 * Example of its usage in src/rsashortAttack.c:49

    // square and multiply with mpz_powm
    mpz_powm(*ciphertext, m, keyPair->e, keyPair->n);

 * Square and Multiply Algorithm for Modular Exponentiation

 * This computes: result = base^exponent mod modulus
 *
 * Example: For base = 5, exponent = 13, modulus = 23, we want to compute (5^13) mod 23 efficiently.

 */
long sqmul(long base, long exponent, long modulus) {

    // This will store binary bits of the exponent in reverse (LSB first)
    int binaryExponent[32];
    // Number of binary bits in the exponent
    int bitCount = 0;
    // Initialize result with base, result = x^1 mod m = x
    unsigned long long result = base;

    // STEP 1: Convert the exponent to binary and store in binaryExponent[]

    // For example, if exponent = 13, binary = 1101, stored as {1, 0, 1, 1}
    while (exponent > 0) {
        binaryExponent[bitCount] = exponent % 2;  // Store remainder (0 or 1)

        exponent /= 2;  // Divide exponent by 2 (shift right)

        bitCount++;    // Count how many bits we've stored
    }

    bitCount--; // for 13 we store {1, 0, 1, 1} so we need to decrement or it will be {1, 0, 1, 1, 0}

    // STEP 2: Perform Square and Multiply from the most significant bit to LSB

    // Loop from bitCount down to 0
    while (bitCount > 0) {
        // Square step: result = (result^2) mod modulus
        result = (result * result) % modulus;

        // Move to next lower bit
        if (binaryExponent[--bitCount] == 1) {
            // Multiply step: result = (result * base) mod modulus
            result = (result * base) % modulus;
        }
        // If the bit was 0, we skip multiplication and continue squaring
    }

    return result;
}

int main() {
    long base, exponent, modulus;
    long result;

    printf("Enter base, exponent, and modulus (such as 5 13 23): ");
    scanf("%ld %ld %ld", &base, &exponent, &modulus);

    result = sqmul(base, exponent, modulus);

    // (base^exponent) mod modulus
    printf("Result: %ld\n", result);

    return EXIT_SUCCESS;
}