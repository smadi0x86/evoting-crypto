#ifndef DES_H
#define DES_H

#include <stdint.h>
#include <stddef.h>

#define DES_BLOCK_SIZE 8

typedef struct {
    // 16 48 bit round keys
    uint64_t roundKeys[16];
} deskeySchedule;

void keySchedule(deskeySchedule *ks, const uint8_t *key);

void desencryptBlock(const deskeySchedule *ks, const uint8_t *plaintext, uint8_t *ciphertext);
void desdecryptBlock(const deskeySchedule *ks, const uint8_t *ciphertext, uint8_t *plaintext);

void cbcEncrypt(const deskeySchedule *ks, const uint8_t *iv,
                    const uint8_t *plaintext, uint8_t *ciphertext,
                    size_t length);
void cbcDecrypt(const deskeySchedule *ks, const uint8_t *iv,
                    const uint8_t *ciphertext, uint8_t *plaintext,
                    size_t length);

void ctsEncrypt(const deskeySchedule *ks, const uint8_t *iv,
                       const uint8_t *plaintext, uint8_t *ciphertext,
                       size_t length);
void ctsDecrypt(const deskeySchedule *ks, const uint8_t *iv,
                       const uint8_t *ciphertext, uint8_t *plaintext,
                       size_t length);

#endif