#include "constants.h"
#include "utils.h"

uint64_t permute(uint64_t input, const uint8_t *table, int outputLength, int inputLength) {

    /*
    https://www.tutorialspoint.com/cprogramming/c_operators.htm

    Example:
        Input: 0b10110010
        Table: {8, 6, 3, 1}
    */
    uint64_t output = 0;

    for (int i = 0; i < outputLength; i++) {

        // bitPosition = 8 - 8 = 0, bitPosition = 8 - 6 = 2
        int bitPosition = inputLength - table[i];

        // input >> 0 & 1 = 0 (LSB is 0), input >> 2 & 1 = 0
        uint64_t selectedBit = (input >> bitPosition) & 1;

        // output = 0 << 1 | 0 = 0b0
        // output = 0 << 1 | 0 = 0b0
        // output = 0 << 1 | 1 = 0b1
        // output = 1 << 1 | 0 = 0b11
        output = (output << 1) | selectedBit;
    }

    // 0b0011 (3)
    return output;
}

uint32_t circularrotateleftBy28(uint32_t value, int bits) {

    // Example: if value is 0x12345678 and bits is 4

    // a mask with 28 bits set to 1 (to keep only the lower 28 bits)
    uint32_t mask = 0x0FFFFFFF;

    // shift left and mask to ensure 28 bits only
    // left = (0x12345678 << 4) & 0x0FFFFFFF
    //      = 0x123456780 << 4 = 0x123456780 (but only 28 bits matter)
    // 0x12345678 << 4 = 0x23456780
    // mask that: 0x23456780 & 0x0FFFFFFF = 0x03456780
    uint32_t left = (value << bits) & mask;

    // shift right to bring "overflow" bits to the lower positions
    // right = 0x12345678 >> (28 - 4) = 0x12345678 >> 24
    // 0x12345678 in binary: 0001 0010 0011 0100 0101 0110 0111 1000
    // >> 24 gives: 0x12 (because 0x12345678 >> 24 = 0x12)
    uint32_t right = value >> (28 - bits);

    // rotated = 0x03456780 | 0x12 = 0x03456792
    uint32_t rotated = left | right;

    // rotated & mask = 0x03456792 & 0x0FFFFFFF = 0x03456792
    return rotated & mask;
}


uint64_t bytestoUint64(const uint8_t *bytes) {

    // convert an array of 8 bytes to a 64 bit integer

    uint64_t result = 0;
    // if key is {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
    // then result will be 0x0102030405060708
    for (int i = 0; i < 8; i++) {

        result = (result << 8) | bytes[i];
    }

    return result;
}

void uint64toBytes(uint64_t value, uint8_t *bytes) {
    for (int i = 7; i >= 0; i--) {

        bytes[i] = value & 0xFF;
        value >>= 8;
    }
}

void printHex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void getInput(const char* prompt, char* buffer, size_t buffer_size) {
    printf("%s", prompt);

    fgets(buffer, buffer_size, stdin);
}

void genrandomdesKey(uint8_t *key) {
    srand(time(NULL));

    for (int i = 0; i < 8; i++) {
        key[i] = rand() % 256;
    }
}

void genrandomIV(uint8_t *iv) {
    for (int i = 0; i < 8; i++) {
        iv[i] = rand() % 256;
    }

    // or we can use /dev/urandom
    // FILE *fptr = fopen("/dev/urandom", "rb");
    // if (fptr == NULL) {
    //     printf("Failed to open /dev/urandom\n");
    //     exit(EXIT_FAILURE);
    // }

    // if (fread(iv, 1, 8, fptr) != 8) {
    //     printf("Failed to read random bytes from /dev/urandom\n");
    //     fclose(fptr);
    //     exit(EXIT_FAILURE);
    // }

    // fclose(fptr);
}

int hextoBytes(const char *hex_str, uint8_t *bytes, size_t bytesLength) {

    size_t hexLength = strlen(hex_str);
    size_t byteCount = hexLength / 2;

    if (byteCount > bytesLength) {
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < byteCount; i++) {
        sscanf(hex_str + (i * 2), "%2hhx", &bytes[i]);
    }

    return EXIT_SUCCESS;
}

void pkcs7Padding(uint8_t *out, const uint8_t *in, size_t length, size_t blocksize) {

    size_t pad = blocksize - (length % blocksize);

    if (pad == blocksize) {
        pad = 0;
    }

    memcpy(out, in, length);

    for (size_t i = 0; i < pad; i++) {
        out[length + i] = (uint8_t)pad;
    }
}