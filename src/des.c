#include <stdio.h>
#include <string.h>
#include "constants.h"
#include "utils.h"
#include "des.h"

/*
DES implementation from scratch based on FIPS 46-3 specification
https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
*/

void keySchedule(deskeySchedule *ks, const uint8_t *key) {

    uint64_t keyBits = bytestoUint64(key);

    // pc1
    uint64_t permuted_key = permute(keyBits, pc1Table, 56, 64);

    // split to c (left) and d (right)
    uint32_t C = (uint32_t)(permuted_key >> 28);
    uint32_t D = (uint32_t)(permuted_key & 0x0FFFFFFF);

    // 16 rounds
    for (int i = 0; i < 16; i++) {

        C = circularrotateleftBy28(C, keyShifts[i]);
        D = circularrotateleftBy28(D, keyShifts[i]);

        uint64_t combined = ((uint64_t)C << 28) | D;

        // pc2
        ks->roundKeys[i] = permute(combined, pc2Table, 48, 56);
    }
}

static uint32_t feistelFunction(uint32_t R, uint64_t roundKey) {

    // from 32 bits to 48 bits
    uint64_t expnadedRound = permute(R, expansionPerm, 48, 32);

    // xor
    expnadedRound ^= roundKey;

    // S-boxes

    uint32_t output = 0;

    for (int i = 0; i < 8; i++) {
        // Extract 6 bit chunks
        int bit_pos = 42 - (i * 6);
        uint8_t s_input = (expnadedRound >> bit_pos) & 0x3F;

        // Calculate row and column for S-box lookup
        uint8_t row = ((s_input & 0x20) >> 4) | (s_input & 0x01);
        uint8_t col = (s_input >> 1) & 0x0F;

        // S-box substitution
        uint8_t s_output = sBoxes[i][row][col];

        // Add to output (4 bits at a time)
        output = (output << 4) | s_output;
    }

    // now do the sbox permutation
    return permute(output, sboxPerm, 32, 32);
}

void desencryptBlock(const deskeySchedule *ks, const uint8_t *plaintext, uint8_t *ciphertext) {

    uint64_t block = bytestoUint64(plaintext);

    block = permute(block, initialPerm, 64, 64);

    // split to LPT and RPT
    uint32_t L = (uint32_t)(block >> 32);
    uint32_t R = (uint32_t)(block & 0xFFFFFFFF);

    // 16 rounds feistel function
    // IMPORTANT, this is what causes bugs and AI will never get it right
    for (int i = 0; i < 16; i++) {
        uint32_t temp = L;
        L = R;
        R = temp ^ feistelFunction(R, ks->roundKeys[i]);
    }

    // swap L and R
    // after 16 rounds, L is the right half and R is the left half
    block = ((uint64_t)R << 32) | L;


    block = permute(block, finalPerm, 64, 64);

    uint64toBytes(block, ciphertext);
}

void desdecryptBlock(const deskeySchedule *ks, const uint8_t *ciphertext, uint8_t *plaintext) {

    uint64_t block = bytestoUint64(ciphertext);

    block = permute(block, initialPerm, 64, 64);

    uint32_t L = (uint32_t)(block >> 32);
    uint32_t R = (uint32_t)(block & 0xFFFFFFFF);

    // 16 rounds: identical to encryption, but keys are read backwards (reverse order)
    // IMPORTANT, this is what causes bugs and AI will never get it right
    for (int i = 15; i >= 0; i--) {
        uint32_t temp = L;
        L = R;
        R = temp ^ feistelFunction(R, ks->roundKeys[i]);
    }

    // now just swap
    block = ((uint64_t)R << 32) | L;

    block = permute(block, finalPerm, 64, 64);

    uint64toBytes(block, plaintext);
}