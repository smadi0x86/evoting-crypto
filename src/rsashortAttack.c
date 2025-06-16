#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <gmp.h>
#include "rsaKeygen.h"
#include "utils.h"
#include "rsa.h"

const char* testCandidates[] = {
    "Alice",
    "Bob",
    "Charlie",
    "Dave",
    "Eve",
    "Frank",
    "Grace",
    "Heidi",
    "Ivan",
    "Judy"
};

const int keySizes[] = {512, 1024, 2048};

// https://gmplib.org/manual/Integer-Exponentiation
int rsaencryptString(const rsakeyPair *keyPair, const char *plaintext, mpz_t *ciphertext) {

    mpz_t m;
    mpz_init(m);

    size_t len = strlen(plaintext);

    mpz_import(m, len, 1, 1, 1, 0, plaintext);

    if (mpz_cmp(m, keyPair->n) >= 0) {
        printf(" Message is too large for the key size\n");
        mpz_clear(m);
        return 0;
    }

    // c = m^e mod n
    mpz_init(*ciphertext);

    // square and multiply with mpz_powm
    mpz_powm(*ciphertext, m, keyPair->e, keyPair->n);

    mpz_clear(m);

    return 1;
}

int rsadecrypttoString(const rsakeyPair *keyPair, const mpz_t ciphertext,
                          char *plaintext, size_t max_len) {
    mpz_t m;
    mpz_init(m);

    // Decrypt: m = c^d mod n
    mpz_powm(m, ciphertext, keyPair->d, keyPair->n);

    // Convert the number back to a string
    size_t bytes_written;

    mpz_export(plaintext, &bytes_written, 1, 1, 1, 0, m);

    // Ensure null termination
    if (bytes_written < max_len) {
        plaintext[bytes_written] = '\0';
    } else {
        plaintext[max_len - 1] = '\0';
    }

    mpz_clear(m);
    return 1;
}

void demchosenciphertextAttack(const rsakeyPair *keyPair) {
    printf("\n----- VULNERABILITY DEMONSTRATION: Chosen Ciphertext Attack -----\n");
    printf("This demonstrates why raw RSA encryption is vulnerable to chosen ciphertext attacks.\n\n");

    const char *original_message = "Vote";

    printf("Original message: \"%s\"\n", original_message);

    mpz_t ciphertext;
    if (!rsaencryptString(keyPair, original_message, &ciphertext)) {
        printf("Encryption failed\n");
        return;
    }

    char *ciphertext_str = mpz_get_str(NULL, 16, ciphertext);

    printf("Ciphertext: %s\n", ciphertext_str);

    free(ciphertext_str);

    // attacker chooses a value s (for simplicity, let's use 2)
    mpz_t s, modified_ciphertext, s_e, decrypted_value;
    mpz_init_set_ui(s, 2);
    mpz_init(modified_ciphertext);
    mpz_init(s_e);
    mpz_init(decrypted_value);

    // s^e mod n
    mpz_powm(s_e, s, keyPair->e, keyPair->n);

    // c' = c * s^e mod n
    mpz_mul(modified_ciphertext, ciphertext, s_e);
    mpz_mod(modified_ciphertext, modified_ciphertext, keyPair->n);

    char *modified_str = mpz_get_str(NULL, 16, modified_ciphertext);
    printf("\nAttacker modifies ciphertext to: %s\n", modified_str);
    free(modified_str);

    char decrypted[256];
    rsadecrypttoString(keyPair, modified_ciphertext, decrypted, sizeof(decrypted));

    // decrypted value will be m' = m * s mod n
    printf("Decrypted modified ciphertext: ");

    for (size_t i = 0; i < strlen(decrypted); i++) {

        printf("%02X ", (unsigned char)decrypted[i]);
    }

    printf("\n");

    printf("\nAttack explanation:\n");
    printf("1. Original message m was encrypted to c = m^e mod n\n");
    printf("2. Attacker chose s=2 and calculated c' = c * (2^e) mod n\n");
    printf("3. When decrypted, this gives m' = m * 2 mod n\n");
    printf("4. This mathematical relationship reveals information about the original message\n");
    printf("5. With carefully chosen values, an attacker could potentially recover the message\n");

    mpz_clear(s);
    mpz_clear(modified_ciphertext);
    mpz_clear(s_e);
    mpz_clear(decrypted_value);
    mpz_clear(ciphertext);
}

void demknownplaintextAttack() {
    printf("\n----- VULNERABILITY DEMONSTRATION: Known Plaintext Attack -----\n");
    printf("This demonstrates why short messages are particularly vulnerable in RSA.\n\n");

    printf("Assume an e-voting system with these 10 candidates:\n");

    for (int i = 0; i < 10; i++) {

        printf("  %d. %s\n", i+1, testCandidates[i]);
    }

    printf("\nAttack scenario:\n");
    printf("1. Attacker knows all possible candidate names (finite, small set)\n");
    printf("2. Attacker intercepts an encrypted vote ciphertext\n");
    printf("3. Attacker can try encrypting each candidate name with the public key\n");
    printf("4. By comparing results, attacker can determine which candidate was voted for\n\n");

    printf("This attack works because:\n");
    printf("- The message space is very small (only 10 possible values)\n");
    printf("- RSA is deterministic (same input always produces same output)\n");
    printf("- No randomized padding is used\n\n");

    printf("With only %d candidates, the attacker needs at most %d encryption operations\n", 10, 10);
    printf("to break the confidentiality of any vote, regardless of key size!\n");
}

void demdirectEncoding(const rsakeyPair *keyPair) {
    printf("\n----- VULNERABILITY DEMONSTRATION: Direct Encoding Issues -----\n");
    printf("This demonstrates issues with directly encoding short strings in RSA.\n\n");

    const char *short_message = "A";
    printf("Testing with very short message: \"%s\"\n", short_message);

    printf("ASCII value: %d (decimal)\n", short_message[0]);

    // how small this value is compared to the modulus
    char *n_str = mpz_get_str(NULL, 10, keyPair->n);
    printf("RSA modulus has approximately %lu digits\n", strlen(n_str));
    free(n_str);

    printf("\nProblem: When directly encoding small values like single characters,\n");
    printf("the numeric value is extremely small compared to the modulus.\n");
    printf("This can be easily brute-forced regardless of key size.\n");

    mpz_t message_value;
    mpz_init(message_value);
    mpz_import(message_value, strlen(short_message), 1, 1, 0, 0, short_message);

    char *message_numeric = mpz_get_str(NULL, 10, message_value);
    printf("\nNumeric representation of \"%s\": %s\n", short_message, message_numeric);
    printf("This small value is trivial to brute force!\n");
    free(message_numeric);

    mpz_clear(message_value);
}

int main() {
    printf("=====================================================\n");
    printf("  RSA SHORT MESSAGE SECURITY ASSESSMENT FOR E-VOTING\n");
    printf("=====================================================\n\n");

    printf("This assessment evaluates the security of using RSA\n");
    printf("directly for encrypting short messages like candidate\n");
    printf("names in an e-voting system.\n\n");

    printf("Generating a 1024-bit RSA key pair for testing...\n");

    rsakeyPair keyPair;
    rsainitkeyPair(&keyPair);

    if (rsagenKey(&keyPair, 1024) != EXIT_SUCCESS) {
        printf("Failed to generate RSA key pair...\n");
        return 1;
    }

    printf("Key generation complete.\n\n");

    printrsakeyInfo(&keyPair);

    printf("\n----- BASIC FUNCTIONALITY DEMONSTRATION -----\n");

    const char *test_message = "Alice";
    printf("Test message: \"%s\"\n", test_message);

    mpz_t ciphertext;

    if (!rsaencryptString(&keyPair, test_message, &ciphertext)) {
        printf("Encryption failed\n");
        rsaclearkeyPair(&keyPair);
        return 1;
    }

    char *ciphertext_str = mpz_get_str(NULL, 16, ciphertext);
    printf("Ciphertext (hex): %s\n", ciphertext_str);
    free(ciphertext_str);

    char decrypted[256];

    if (!rsadecrypttoString(&keyPair, ciphertext, decrypted, sizeof(decrypted))) {

        printf("Decryption failed\n");

        mpz_clear(ciphertext);
        rsaclearkeyPair(&keyPair);

        return 1;
    }

    printf("Decrypted: \"%s\"\n", decrypted);

    if (strcmp(decrypted, test_message) == 0) {
        printf("Encryption/decryption test passed!\n");
    } else {
        printf("Encryption/decryption test failed!\n");
    }

    printf("\n----- TESTING DIFFERENT MESSAGE LENGTHS -----\n");
    const char *messages[] = {"A", "Bob", "Charlie", "This is a longer candidate name"};
    for (int i = 0; i < 4; i++) {
        printf("\nMessage: \"%s\" (Length: %zu)\n", messages[i], strlen(messages[i]));

        if (strlen(messages[i]) * 8 > 1024) {
            printf("Message too long for this key size - would need to be split\n");
            continue;
        }

        // encrypt
        mpz_t ct;
        if (!rsaencryptString(&keyPair, messages[i], &ct)) {
            printf("Encryption failed\n");
            continue;
        }

        // decrypt
        char dec[256];
        if (!rsadecrypttoString(&keyPair, ct, dec, sizeof(dec))) {
            printf("Decryption failed\n");
            mpz_clear(ct);
            continue;
        }

        printf("Decrypted: \"%s\"\n", dec);
        if (strcmp(dec, messages[i]) == 0) {
            printf("Test passed!\n");
        } else {
            printf("Test failed!\n");
        }

        mpz_clear(ct);
    }

    demdirectEncoding(&keyPair);
    demknownplaintextAttack();
    demchosenciphertextAttack(&keyPair);

    mpz_clear(ciphertext);
    rsaclearkeyPair(&keyPair);

    return 0;
}