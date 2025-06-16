#include <stdio.h>
#include "../src/constants.h"
#include "../src/utils.h"
#include "../src/des.h"


void hexstrtoBytes(const char *hex, uint8_t *out) {
    for (int i = 0; i < 8; i++) {
        sscanf(hex + 2*i, "%2hhx", &out[i]);
    }
}

int main(){
    const char *hexstr = "123456ABCD132536";

    uint8_t blockBytes[8];
    hexstrtoBytes(hexstr, blockBytes);

    uint64_t block = bytestoUint64(blockBytes);

    block = permute(block, initialPerm, 64, 64);

    printf("After initial permutation: ");
    printHex((const uint8_t *)&block, 8);

}