#include <time.h>
#include "evoting.h"
#include "utils.h"
#include "sha256.h"

void evoteInit(evote_t *vote) {
    // man memset
    memset(vote->candidateName, 0, sizeof(vote->candidateName));
    memset(vote->des_key, 0, sizeof(vote->des_key));
    memset(vote->iv, 0, sizeof(vote->iv));

    rsainitkeyPair(&vote->keyPair);

    vote->mode = MODE_BOTH;
}

void evotecleanUp(evote_t *vote) {
    rsaclearkeyPair(&vote->keyPair);
}

void secureevoteInit(secureEvote_t *secureVote) {
    secureVote->encryptedData = NULL;
    secureVote->encryptedLength = 0;

    mpz_init(secureVote->signature);

    memset(secureVote->iv, 0, sizeof(secureVote->iv));

    secureVote->mode = MODE_BOTH;
}

void secureevotecleanUp(secureEvote_t *secureVote) {

    // check if secureVote points to some data
    if (secureVote->encryptedData) {
        // free the data and set ptr to null
        free(secureVote->encryptedData);
        secureVote->encryptedData = NULL;
    }

    mpz_clear(secureVote->signature);
}

int processVote(const evote_t *vote, secureEvote_t *secureVote) {

    // get user chosen mode
    secureVote->mode = vote->mode;

    // get IV from the vote for reference
    memcpy(secureVote->iv, vote->iv, sizeof(secureVote->iv));

    // check of each mode so we can proceed accordingly

    if (vote->mode == MODE_CONFIDENTIALITY || vote->mode == MODE_BOTH) {

        size_t messageLength = strlen(vote->candidateName);

        deskeySchedule ks;
        keySchedule(&ks, vote->des_key);

        if (messageLength == 0) {
            fprintf(stderr, "Candidate name is empty, cannot encrypt\n");

            return EXIT_FAILURE;

        } else if (messageLength <= DES_BLOCK_SIZE) {
            // pad with PKCS#7 if < 8
            uint8_t paddedBlock[DES_BLOCK_SIZE];

            pkcs7Padding(paddedBlock, (const uint8_t *)vote->candidateName, messageLength, DES_BLOCK_SIZE);

            secureVote->encryptedData = (uint8_t *)malloc(DES_BLOCK_SIZE);

            if (!secureVote->encryptedData) {
                fprintf(stderr, "Memory allocation failed\n");

                return EXIT_FAILURE;
            }

            cbcEncrypt(&ks, vote->iv, paddedBlock, secureVote->encryptedData, DES_BLOCK_SIZE);

            secureVote->encryptedLength = DES_BLOCK_SIZE;

        } else if (messageLength % DES_BLOCK_SIZE == 0) {
            // if multiple of 8, use CBC
            secureVote->encryptedData = (uint8_t *)malloc(messageLength);
            if (!secureVote->encryptedData) {
                fprintf(stderr, "Memory allocation failed\n");
                return EXIT_FAILURE;
            }
            cbcEncrypt(&ks, vote->iv, (const uint8_t *)vote->candidateName,
                    secureVote->encryptedData, messageLength);
            secureVote->encryptedLength = messageLength;
        } else {
            // CTS for != blocksize and > 8
            secureVote->encryptedData = (uint8_t *)malloc(messageLength);

            if (!secureVote->encryptedData) {
                fprintf(stderr, "Memory allocation failed\n");

                return EXIT_FAILURE;
            }

            ctsEncrypt(&ks, vote->iv, (const uint8_t *)vote->candidateName,
                    secureVote->encryptedData, messageLength);

            secureVote->encryptedLength = messageLength;
        }
    }

    if (vote->mode == MODE_AUTHENTICATION || vote->mode == MODE_BOTH) {


        const unsigned char *datatoSign;
        size_t dataLength;

        if (vote->mode == MODE_BOTH) {
            // just sign encrypted data
            datatoSign = secureVote->encryptedData;
            dataLength = secureVote->encryptedLength;

        } else {
            // just sign plaintext candidate name
            datatoSign = (const unsigned char *)vote->candidateName;
            dataLength = strlen(vote->candidateName);
        }

        // get SHA-256 hash of the data to sign
        uint8_t hash[SHA256_SIZE_BYTES];

        sha256_context sha256_ctx;

        sha256_init(&sha256_ctx);
        sha256_hash(&sha256_ctx, datatoSign, dataLength);
        sha256_done(&sha256_ctx, hash);

        // just sign the hash and check if its successful
        if (rsaSign(&vote->keyPair, hash, SHA256_SIZE_BYTES, &secureVote->signature) != EXIT_SUCCESS) {

            fprintf(stderr, "Failed to sign the vote\n");

            if (secureVote->encryptedData) {

                free(secureVote->encryptedData);
                secureVote->encryptedData = NULL;
            }

            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int verifyVote(const secureEvote_t *secureVote, const evote_t *vote_info,
                char *candidateName, size_t candidateName_size) {

    // add result var set to 1
    int result = 1;

    if (secureVote->mode == MODE_AUTHENTICATION || secureVote->mode == MODE_BOTH) {
        const unsigned char *datatoVerify;
        size_t dataLength;

        if (secureVote->mode == MODE_BOTH) {

            datatoVerify = secureVote->encryptedData;
            dataLength = secureVote->encryptedLength;
        } else {

            // cast candidateName to unsigned char ptr
            datatoVerify = (const unsigned char *)candidateName;

            dataLength = strlen(candidateName);
        }

        uint8_t hash[SHA256_SIZE_BYTES];
        sha256_context sha256_ctx;

        sha256_init(&sha256_ctx);
        sha256_hash(&sha256_ctx, datatoVerify, dataLength);
        sha256_done(&sha256_ctx, hash);


        if (!rsaVerify(&vote_info->keyPair, hash, SHA256_SIZE_BYTES,
                       secureVote->signature)) {
            fprintf(stderr, "Signature verification failed...\n");

            result = 0;

        } else {

            printf("SIGNATURE SUCCESS!\n");
        }
    }

    if ((secureVote->mode == MODE_CONFIDENTIALITY || secureVote->mode == MODE_BOTH) && result) {

        deskeySchedule ks;
        keySchedule(&ks, vote_info->des_key);

        // alloc mem for decrypted data
        // +1 for null terminator
        uint8_t *decrypted = (uint8_t *)malloc(secureVote->encryptedLength + 1);

        if (!decrypted) {

            fprintf(stderr, "Memory allocation failed\n");

            return EXIT_FAILURE;
        }

        ctsDecrypt(&ks, secureVote->iv, secureVote->encryptedData,
                           decrypted, secureVote->encryptedLength);

        // null terminate the decrypted data, so we dont need to de-pad cbcDecrypt function
        decrypted[secureVote->encryptedLength] = '\0';

        strncpy(candidateName, (char *)decrypted, candidateName_size - 1);

        candidateName[candidateName_size - 1] = '\0';

        free(decrypted);
    }

    return result;
}

void printsecurevoteInfo(const secureEvote_t *secureVote) {

    printf("Operation mode: ");

    switch (secureVote->mode) {
        case MODE_CONFIDENTIALITY:
            printf("Confidentiality Only (Encryption)\n");
            break;
        case MODE_AUTHENTICATION:
            printf("Authentication Only (Digital Signature)\n");
            break;
        case MODE_BOTH:
            printf("Both Confidentiality and Authentication\n");
            break;
        default:
            printf("Something went wrong, unknown :(\n");
    }

    printf("IV: ");
    printHex(secureVote->iv, 8);

    if (secureVote->mode == MODE_CONFIDENTIALITY || secureVote->mode == MODE_BOTH) {
        printf("Encrypted Data (%zu bytes): ", secureVote->encryptedLength);

        printHex(secureVote->encryptedData, secureVote->encryptedLength);
    }

    if (secureVote->mode == MODE_AUTHENTICATION || secureVote->mode == MODE_BOTH) {
        char *signatureString = mpz_get_str(NULL, 16, secureVote->signature);

        printf("Digital signature (hex): %s\n", signatureString);

        free(signatureString);
    }

    printf("\n");
}

void printvoteInfo(const evote_t *vote) {
    printf("-------------- Vote Information --------------n");

    printf("Candidate name: %s\n", vote->candidateName);

    printf("DES key: ");
    printHex(vote->des_key, 8);

    printf("IV: ");
    printHex(vote->iv, 8);

    printf("Operation mode: ");

    switch (vote->mode) {
        case MODE_CONFIDENTIALITY:
            printf("Confidentiality Only (Encryption)\n");
            break;
        case MODE_AUTHENTICATION:
            printf("Authentication Only (Digital Signature)\n");
            break;
        case MODE_BOTH:
            printf("Both Confidentiality and Authentication\n");
            break;
        default:
            printf("Something went wrong, unknown :(\n");
    }

    printf("RSA key info:\n");

    printrsakeyInfo(&vote->keyPair);
}