#ifndef EVOTING_H
#define EVOTING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <gmp.h>
#include "des.h"
#include "rsa.h"
#include "rsaKeygen.h"

typedef enum {
    // DES (symmetric encryption) w/ CBC and CTS modes
    MODE_CONFIDENTIALITY = 1,
    // Digital Signature (rsa) w/ SHA-256 hash
    MODE_AUTHENTICATION = 2,
    MODE_BOTH = 3
} evotingMode;

typedef struct {
    char candidateName[256];
    uint8_t des_key[8];
    uint8_t iv[8];
    rsakeyPair keyPair;
    evotingMode mode;
} evote_t;

typedef struct {
    uint8_t *encryptedData;
    size_t encryptedLength;
    mpz_t signature;
    uint8_t iv[8];
    evotingMode mode;
} secureEvote_t;

void evoteInit(evote_t *vote);
void evotecleanUp(evote_t *vote);
void secureevoteInit(secureEvote_t *secureVote);
void secureevotecleanUp(secureEvote_t *secureVote);
int processVote(const evote_t *vote, secureEvote_t *secureVote);
int verifyVote(const secureEvote_t *secureVote, const evote_t *vote_info,
                char *candidateName, size_t candidateName_size);
void printsecurevoteInfo(const secureEvote_t *secureVote);
void printvoteInfo(const evote_t *vote);

#endif