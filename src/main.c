#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "rsaKeygen.h"
#include "evoting.h"
#include "utils.h"
#include "des.h"
#include "rsa.h"

/*
    PART 1: E-voting Implementation
*/

int main() {

    // create object of struct evote_t
    evote_t vote;

    // alloc memory for the vote
    evoteInit(&vote);

    getInput("Enter candidate name: ",
               vote.candidateName, sizeof(vote.candidateName));

    char modeString[10];

    printf("\nWhat do you want?\n");

    printf("1) Confidentiality oly (Encryption)\n");
    printf("2) Authentication only (Digital Signature)\n");
    printf("3) Both\n");

    getInput("Enter your choice (1-3): ", modeString, sizeof(modeString));

    int mode = atoi(modeString);

    if (mode < MODE_CONFIDENTIALITY || mode > MODE_BOTH) {
        printf("I told you to pick from 1 - 3, exiting...\n");

        exit(EXIT_FAILURE);
    }

    // cast mode to enum evotingMode
    vote.mode = (evotingMode)mode;


    // now we just check based on mode

    // ------------- RSA

    if (vote.mode == MODE_AUTHENTICATION || vote.mode == MODE_BOTH) {
        printf("\n------------------------- AUTHENTICATION -------------------------\n");

        char rsa_option[10];
        printf("1. Generate random RSA key (recommended)\n");
        printf("2. Provide custom prime numbers\n");
        getInput("Select an option (1-2): ", rsa_option, sizeof(rsa_option));

        if (rsa_option[0] == '1') {

            char keysizeString[10];

            getInput("Enter RSA key size in bits (1024, 2048, 4096 - default: 1024): ",
                       keysizeString, sizeof(keysizeString));

            // if user doesnt choose

            unsigned int keyBits = 1024;

            // if user provided keysize, convert it to int
            if (strlen(keysizeString) > 0) {
                keyBits = atoi(keysizeString);
            }

            // now we create keys

            printf("Creating a %u bit RSA key pair...\n", keyBits);

            if (rsagenKey(&vote.keyPair, keyBits) != EXIT_SUCCESS) {
                printf("Failed to generate RSA key pair!\n");

                evotecleanUp(&vote);

                return EXIT_FAILURE;
            }
        } else {
            // user will give us p, q and e

            char p_str[1024], q_str[1024], e_str[1024];

            getInput("Enter prime number p: ", p_str, sizeof(p_str));

            if (!isPrime(p_str)) {
                printf(" %s is not a prime number.\n", p_str);

                evotecleanUp(&vote);

                return EXIT_FAILURE;
            }

            getInput("Enter prime number q: ", q_str, sizeof(q_str));

            if (!isPrime(q_str)) {
                printf(" %s is not a prime number.\n", q_str);

                evotecleanUp(&vote);

                return EXIT_FAILURE;
            }

            getInput("Enter public exponent e (default: 65537): ", e_str, sizeof(e_str));

            // if user is dumb, just use 65537
            if (strlen(e_str) == 0) {
                strcpy(e_str, "65537");
            }

            if (rsagenkeyPair(&vote.keyPair, p_str, q_str, e_str) != EXIT_SUCCESS) {
                printf("Failed to generate RSA key pair :(\n");

                evotecleanUp(&vote);

                return EXIT_FAILURE;
            }
        }
    }

    // ------------- DES

    if (vote.mode == MODE_CONFIDENTIALITY || vote.mode == MODE_BOTH) {
        printf("\n------------------------- CONFIDENTIAL MODE -------------------------\n");

        char desOption[10];

        printf("1) Generate random DES key (recommended)\n");
        printf("2) Provide custom DES key (8 bytes, hex format)\n");

        getInput("Choose an option (1-2): ", desOption, sizeof(desOption));

        if (desOption[0] == '1') {
            genrandomdesKey(vote.des_key);

            printf("The generated DES key: ");

            printHex(vote.des_key, 8);
        } else {
            // let user input

            char deskeyHex[20];
            getInput("Enter DES key (16 hex characters): ", deskeyHex, sizeof(deskeyHex));

            if (strlen(deskeyHex) != 16 || !hextoBytes(deskeyHex, vote.des_key, 8)) {
                printf("you can't even specify a simple key, just using a random key.\n");

                genrandomdesKey(vote.des_key);
            }
        }

        genrandomIV(vote.iv);

        printf("IV: ");
        printHex(vote.iv, 8);
    }


    secureEvote_t secureVote;
    secureevoteInit(&secureVote);

    printf("\nProcessing vote for '%s'...\n", vote.candidateName);

    if (processVote(&vote, &secureVote) != EXIT_SUCCESS) {
        printf("Failed to process vote...\n");

        evotecleanUp(&vote);
        secureevotecleanUp(&secureVote);

        return EXIT_FAILURE;
    }

    printf("\n------------------------- Original Vote -------------------------\n");
    printvoteInfo(&vote);

    printf("\n------------------------- Secure Vote (After processing) -------------------------\n");
    printsecurevoteInfo(&secureVote);

    // now just confirm

    printf("\nVerifying and decrypting the vote...\n");
    char recoveredCandidate[256];

    if (vote.mode == MODE_AUTHENTICATION) {

        strncpy(recoveredCandidate, vote.candidateName, sizeof(recoveredCandidate) - 1);

        recoveredCandidate[sizeof(recoveredCandidate) - 1] = '\0';
    }

    if (verifyVote(&secureVote, &vote, recoveredCandidate, sizeof(recoveredCandidate))) {
        printf("Vote verification successful!\n");

        if (vote.mode == MODE_CONFIDENTIALITY || vote.mode == MODE_BOTH) {
            printf("decrypted candidate name: %s\n", recoveredCandidate);
        }

    } else {
        printf("vote verification failed...\n");
    }

    evotecleanUp(&vote);
    secureevotecleanUp(&secureVote);

    return EXIT_SUCCESS;
}