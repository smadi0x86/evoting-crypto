#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCK_LEN 16

// https://github.com/BrianGladman/aes/blob/master/aesxam.c

int main() {
    // 3*BLOCK_LEN is used in original code to handle ciphertext stealing
    // which requires 3 blocks: IV, current block, and next block
    unsigned char dbuf[3 * BLOCK_LEN];
    unsigned long i, len;

    // Set random IV, time(NULL) is used as seed (differs each run), IV must be random and different for each run
    srand(time(NULL));
    for (i = 0; i < BLOCK_LEN; i++) {
        dbuf[i] = rand() % 256;
    }

    printf("give chars < %d: ", BLOCK_LEN);
    char input[BLOCK_LEN];

    fgets(input, sizeof(input), stdin);
    len = strlen(input);

    if (input[len - 1] == '\n') input[--len] = '\0';

    memcpy(dbuf + BLOCK_LEN, input, len);

    printf("before we xor:\n");

    printf("our input:  ");
    for (i = 0; i < BLOCK_LEN; i++) printf("%02x ", dbuf[i + BLOCK_LEN]);
    printf("\n");

    if (len < BLOCK_LEN) {

        printf("executing len < BLOCK_LEN (%lu < %d), xor...\n", len, BLOCK_LEN);

        for(i = 0; i < len; ++i) {
            dbuf[i + BLOCK_LEN] ^= dbuf[i];
        }

        printf("\n");
        printf("after we xor:\n");
        printf("the iv:    ");
        for (i = 0; i < BLOCK_LEN; i++) printf("%02x ", dbuf[i]);
        printf("\nthe xor:  ");
        for (i = 0; i < BLOCK_LEN; i++) printf("%02x ", dbuf[i + BLOCK_LEN]);

        // now just encrypt from dbuf+len and write IV + encrypted data

    }

    return 0;
}