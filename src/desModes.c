#include <stdio.h>
#include <string.h>
#include "des.h"

void cbcEncrypt(const deskeySchedule *ks, const uint8_t *iv,
                   const uint8_t *plaintext, uint8_t *ciphertext,
                   size_t length) {

    uint8_t chain[DES_BLOCK_SIZE];
    uint8_t block[DES_BLOCK_SIZE];

    // iv for first chain block
    memcpy(chain, iv, DES_BLOCK_SIZE);

    // if length is 8, then 8/8 = 1, so we loop once
    size_t blockNumber = length / DES_BLOCK_SIZE;

    for (size_t i = 0; i < blockNumber; i++) {
        for (int j = 0; j < DES_BLOCK_SIZE; j++) {
            // xor plaintext with the chain (IV for first block)
            block[j] = plaintext[i * DES_BLOCK_SIZE + j] ^ chain[j];
        }

        desencryptBlock(ks, block, ciphertext + i * DES_BLOCK_SIZE);

        // now update the chain with the current ciphertext block
        memcpy(chain, ciphertext + i * DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    }
}

void cbcDecrypt(const deskeySchedule *ks, const uint8_t *iv,
                   const uint8_t *ciphertext, uint8_t *plaintext,
                   size_t length) {
    uint8_t chain[DES_BLOCK_SIZE];
    uint8_t block[DES_BLOCK_SIZE];

    memcpy(chain, iv, DES_BLOCK_SIZE);

    size_t blockNumber = length / DES_BLOCK_SIZE;

    for (size_t i = 0; i < blockNumber; i++) {
        // Save current ciphertext block for chaining
        uint8_t current_cipher[DES_BLOCK_SIZE];
        memcpy(current_cipher, ciphertext + i * DES_BLOCK_SIZE, DES_BLOCK_SIZE);

        desdecryptBlock(ks, current_cipher, block);

        // XOR with previous ciphertext block (or IV for first block)
        for (int j = 0; j < DES_BLOCK_SIZE; j++) {
            plaintext[i * DES_BLOCK_SIZE + j] = block[j] ^ chain[j];
        }

        // Update chain for next iteration
        memcpy(chain, current_cipher, DES_BLOCK_SIZE);
    }
}

void ctsEncrypt(const deskeySchedule *ks, const uint8_t *iv,
                       const uint8_t *plaintext, uint8_t *ciphertext,
                       size_t length) {

    // if length is a multiple of block size
    if (length % DES_BLOCK_SIZE == 0) {
        // use regular cbc
        cbcEncrypt(ks, iv, plaintext, ciphertext, length);

        return;
    }

    // calculate number of blocks and size of the last partial block
    size_t blockNumber = length / DES_BLOCK_SIZE;
    size_t last_block_size = length % DES_BLOCK_SIZE;

    if (blockNumber == 0) {
        printf("Message too short for CTS\n");
        return;
    }

    // 1. Encrypt all blocks except the last two using regular CBC mode
    if (blockNumber > 1) {
        cbcEncrypt(ks, iv, plaintext, ciphertext, (blockNumber - 1) * DES_BLOCK_SIZE);
    }

    // 2. Set up the IV for the second to last block
    uint8_t chain[DES_BLOCK_SIZE];
    if (blockNumber > 1) {
        // use the last encrypted block as the IV
        memcpy(chain, ciphertext + (blockNumber - 2) * DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    } else {
        // use the provided IV
        memcpy(chain, iv, DES_BLOCK_SIZE);
    }

    // 3. Create and encrypt the second-to-last plaintext block
    uint8_t block_n_1[DES_BLOCK_SIZE];  // second-to-last block
    uint8_t cipher_n_1[DES_BLOCK_SIZE]; // second-to-last ciphertext

    // XOR with the chain
    for (size_t i = 0; i < DES_BLOCK_SIZE; i++) {
        block_n_1[i] = plaintext[(blockNumber - 1) * DES_BLOCK_SIZE + i] ^ chain[i];
    }

    // Encrypt the XORed block
    desencryptBlock(ks, block_n_1, cipher_n_1);

    // 4. Create the last block (padded with zeros)
    uint8_t block_n[DES_BLOCK_SIZE];  // last block
    memset(block_n, 0, DES_BLOCK_SIZE);
    memcpy(block_n, plaintext + blockNumber * DES_BLOCK_SIZE, last_block_size);

    // 5. XOR the last block with the previous ciphertext
    for (size_t i = 0; i < DES_BLOCK_SIZE; i++) {
        block_n[i] ^= cipher_n_1[i];
    }

    // 6. Encrypt the last block
    uint8_t cipher_n[DES_BLOCK_SIZE]; // last ciphertext
    desencryptBlock(ks, block_n, cipher_n);

    // 7. Ciphertext stealing: the last block is truncated to the same size as the partial plaintext
    // block, and the second-to-last ciphertext is modified to include the remaining bytes

    // First, copy the last full ciphertext block to the second-to-last position
    memcpy(ciphertext + (blockNumber - 1) * DES_BLOCK_SIZE, cipher_n, DES_BLOCK_SIZE);

    // Then, copy the partial ciphertext to the last position
    memcpy(ciphertext + blockNumber * DES_BLOCK_SIZE, cipher_n_1, last_block_size);
}

void ctsDecrypt(const deskeySchedule *ks, const uint8_t *iv,
                       const uint8_t *ciphertext, uint8_t *plaintext,
                       size_t length) {
    // If length is a multiple of block size, use regular CBC
    if (length % DES_BLOCK_SIZE == 0) {
        cbcDecrypt(ks, iv, ciphertext, plaintext, length);
        return;
    }

    // Calculate number of blocks and size of the last partial block
    size_t blockNumber = length / DES_BLOCK_SIZE;
    size_t last_block_size = length % DES_BLOCK_SIZE;

    // We need at least one full block for CTS
    if (blockNumber == 0) {
        printf("Message too short for CTS\n");
        return;
    }

    // 1. Decrypt all blocks except the last two using regular CBC mode
    if (blockNumber > 1) {
        cbcDecrypt(ks, iv, ciphertext, plaintext, (blockNumber - 2) * DES_BLOCK_SIZE);
    }

    // 2. Set up the IV for the second-to-last block
    uint8_t prev_cipher[DES_BLOCK_SIZE];
    if (blockNumber > 1) {
        // Use the last fully decrypted block as the IV
        memcpy(prev_cipher, ciphertext + (blockNumber - 3) * DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    } else {
        // Use the provided IV
        memcpy(prev_cipher, iv, DES_BLOCK_SIZE);
    }

    // 3. Reconstruct the original ciphertext blocks

    // Get the last full ciphertext block (C_n)
    uint8_t cipher_n[DES_BLOCK_SIZE];
    memcpy(cipher_n, ciphertext + (blockNumber - 1) * DES_BLOCK_SIZE, DES_BLOCK_SIZE);

    // Get the partial ciphertext block (C_{n-1})
    uint8_t cipher_n_1[DES_BLOCK_SIZE];
    memset(cipher_n_1, 0, DES_BLOCK_SIZE);
    memcpy(cipher_n_1, ciphertext + blockNumber * DES_BLOCK_SIZE, last_block_size);

    // 4. Decrypt the last full block (C_n)
    uint8_t temp[DES_BLOCK_SIZE];
    desdecryptBlock(ks, cipher_n, temp);

    // 5. Reconstruct the original last ciphertext block by stealing from the second-to-last
    // The last part of C_{n-1} is taken from the decrypted C_n
    for (size_t i = last_block_size; i < DES_BLOCK_SIZE; i++) {
        cipher_n_1[i] = temp[i];
    }

    // 6. Decrypt the reconstructed second-to-last block
    desdecryptBlock(ks, cipher_n_1, temp);

    // 7. XOR with the previous ciphertext block to get P_{n-1}
    for (size_t i = 0; i < DES_BLOCK_SIZE; i++) {
        plaintext[(blockNumber - 1) * DES_BLOCK_SIZE + i] = temp[i] ^ prev_cipher[i];
    }

    // 8. XOR the decrypted last block with the original second-to-last ciphertext to get P_n
    desdecryptBlock(ks, cipher_n, temp);
    for (size_t i = 0; i < last_block_size; i++) {
        plaintext[blockNumber * DES_BLOCK_SIZE + i] = temp[i] ^ cipher_n_1[i];
    }
}