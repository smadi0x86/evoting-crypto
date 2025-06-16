#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "utils.h"
#include "des.h"

/*
    PART 2: Encryption using ECB and CBC modes

    https://en.wikipedia.org/wiki/BMP_file_format
    https://learn.microsoft.com/en-us/windows/win32/gdi/bitmap-structures
    https://stackoverflow.com/questions/14279242/read-bitmap-file-into-structure
    https://github.com/flightcrank/libbmp/blob/master/bmp.c
    https://berkedemiir.medium.com/how-to-threshold-bmp-images-in-c-8aba6be09be4
*/
// BMP file header structure (14 bytes)
typedef struct {
    char signature[2];      // "BM"
    uint32_t fileSize;      // Size of the BMP file in bytes
    uint16_t reserved1;     // Reserved
    uint16_t reserved2;     // Reserved
    uint32_t dataOffset;    // Offset to the start of image data
} __attribute__((packed)) BMPHeader;

// BMP info header structure (40 bytes)
typedef struct {
    uint32_t headerSize;     // Size of this header (40 bytes)
    int32_t width;           // Image width in pixels
    int32_t height;          // Image height in pixels
    uint16_t planes;         // Number of color planes (must be 1)
    uint16_t bitsPerPixel;   // Number of bits per pixel
    uint32_t compression;    // Compression method
    uint32_t imageSize;      // Size of the raw image data
    int32_t xPixelsPerMeter; // Horizontal resolution
    int32_t yPixelsPerMeter; // Vertical resolution
    uint32_t colorsUsed;     // Number of colors in the palette
    uint32_t importantColors;// Number of important colors
} __attribute__((packed)) BMPInfoHeader;

// BMP image structure
typedef struct {
    BMPHeader header;
    BMPInfoHeader infoHeader;
    uint8_t *palette;
    uint8_t *data;
} BMPImage;

BMPImage* readBMPFile(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file %s\n", filename);
        return NULL;
    }

    BMPImage *bmp = (BMPImage*)malloc(sizeof(BMPImage));
    if (!bmp) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    if (fread(&bmp->header, sizeof(BMPHeader), 1, file) != 1) {
        fprintf(stderr, "Error reading BMP header\n");
        free(bmp);
        fclose(file);
        return NULL;
    }

    if (bmp->header.signature[0] != 'B' || bmp->header.signature[1] != 'M') {
        fprintf(stderr, "Not a valid BMP file\n");
        free(bmp);
        fclose(file);
        return NULL;
    }

    if (fread(&bmp->infoHeader, sizeof(BMPInfoHeader), 1, file) != 1) {
        fprintf(stderr, "Error reading BMP info header\n");
        free(bmp);
        fclose(file);
        return NULL;
    }

    int paletteSize = 0;
    if (bmp->infoHeader.bitsPerPixel <= 8) {
        paletteSize = (1 << bmp->infoHeader.bitsPerPixel) * 4; // 4 bytes per palette entry
    }

    if (paletteSize > 0) {
        bmp->palette = (uint8_t*)malloc(paletteSize);
        if (!bmp->palette) {
            fprintf(stderr, "Memory allocation for palette failed\n");
            free(bmp);
            fclose(file);
            return NULL;
        }

        // Read the palette
        if (fread(bmp->palette, paletteSize, 1, file) != 1) {
            fprintf(stderr, "Error reading palette\n");
            free(bmp->palette);
            free(bmp);
            fclose(file);
            return NULL;
        }
    } else {
        bmp->palette = NULL;
    }

    // file pointer to start of image data
    fseek(file, bmp->header.dataOffset, SEEK_SET);

    size_t dataSize = bmp->infoHeader.imageSize;
    if (dataSize == 0) {
        // Some BMP files don't set imageSize correctly, so calculate it
        int bytesPerPixel = bmp->infoHeader.bitsPerPixel / 8;
        if (bmp->infoHeader.bitsPerPixel % 8 != 0) bytesPerPixel++;

        // Calculate row size (must be multiple of 4 bytes)
        int rowSize = (bmp->infoHeader.width * bytesPerPixel + 3) & ~3;
        dataSize = rowSize * abs(bmp->infoHeader.height);
    }

    bmp->data = (uint8_t*)malloc(dataSize);
    if (!bmp->data) {
        fprintf(stderr, "Memory allocation for image data failed\n");
        if (bmp->palette) free(bmp->palette);
        free(bmp);
        fclose(file);
        return NULL;
    }

    if (fread(bmp->data, dataSize, 1, file) != 1) {
        fprintf(stderr, "Error reading image data\n");
        free(bmp->data);
        if (bmp->palette) free(bmp->palette);
        free(bmp);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return bmp;
}

int writeBMPFile(const char *filename, BMPImage *bmp) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error opening file %s for writing\n", filename);

        return EXIT_FAILURE;
    }

    if (fwrite(&bmp->header, sizeof(BMPHeader), 1, file) != 1) {
        fprintf(stderr, "Error writing BMP header\n");
        fclose(file);

        return EXIT_FAILURE;
    }

    if (fwrite(&bmp->infoHeader, sizeof(BMPInfoHeader), 1, file) != 1) {
        fprintf(stderr, "Error writing BMP info header\n");
        fclose(file);

        return EXIT_FAILURE;
    }

    if (bmp->palette) {
        int paletteSize = (1 << bmp->infoHeader.bitsPerPixel) * 4;
        if (fwrite(bmp->palette, paletteSize, 1, file) != 1) {
            fprintf(stderr, "Error writing palette\n");
            fclose(file);

            return EXIT_FAILURE;
        }
    }

    size_t dataSize = bmp->infoHeader.imageSize;
    if (dataSize == 0) {
        int bytesPerPixel = bmp->infoHeader.bitsPerPixel / 8;
        if (bmp->infoHeader.bitsPerPixel % 8 != 0) bytesPerPixel++;

        int rowSize = (bmp->infoHeader.width * bytesPerPixel + 3) & ~3;
        dataSize = rowSize * abs(bmp->infoHeader.height);
    }

    fseek(file, bmp->header.dataOffset, SEEK_SET);

    if (fwrite(bmp->data, dataSize, 1, file) != 1) {
        fprintf(stderr, "Error writing image data\n");
        fclose(file);

        return EXIT_FAILURE;
    }

    fclose(file);

    return EXIT_SUCCESS;
}

void freeBMPImage(BMPImage *bmp) {
    if (bmp) {
        if (bmp->data) free(bmp->data);
        if (bmp->palette) free(bmp->palette);
        free(bmp);
    }
}

void ecbEncrypt(const deskeySchedule *ks, const uint8_t *plaintext,
                    uint8_t *ciphertext, size_t length) {

    size_t blockNumber = length / DES_BLOCK_SIZE;

    for (size_t i = 0; i < blockNumber; i++) {

        // encrypt each block independently
        desencryptBlock(ks, plaintext + i * DES_BLOCK_SIZE,
                         ciphertext + i * DES_BLOCK_SIZE);
    }

    size_t remainder = length % DES_BLOCK_SIZE;

    if (remainder > 0) {
        uint8_t lastBlock[DES_BLOCK_SIZE];
        memcpy(lastBlock, plaintext + blockNumber * DES_BLOCK_SIZE, remainder);

        // 0s pad
        memset(lastBlock + remainder, 0, DES_BLOCK_SIZE - remainder);

        desencryptBlock(ks, lastBlock, ciphertext + blockNumber * DES_BLOCK_SIZE);
    }
}

int encryptBMP_ECB(const char *inputFile, const char *outputFile, const uint8_t *key) {

    BMPImage *bmp = readBMPFile(inputFile);
    if (!bmp) {
        fprintf(stderr, "Failed to read input BMP file\n");

        return EXIT_FAILURE;
    }

    deskeySchedule ks;
    keySchedule(&ks, key);

    size_t dataSize = bmp->infoHeader.imageSize;
    if (dataSize == 0) {
        int bytesPerPixel = bmp->infoHeader.bitsPerPixel / 8;
        if (bmp->infoHeader.bitsPerPixel % 8 != 0) bytesPerPixel++;

        int rowSize = (bmp->infoHeader.width * bytesPerPixel + 3) & ~3;
        dataSize = rowSize * abs(bmp->infoHeader.height);
    }

    uint8_t *encryptedData = (uint8_t*)malloc(dataSize);
    if (!encryptedData) {
        fprintf(stderr, "Memory allocation for encrypted data failed\n");
        freeBMPImage(bmp);

        return EXIT_FAILURE;
    }

    printf("ECB Mode: Encrypting %zu bytes of pixel data...\n", dataSize);
    ecbEncrypt(&ks, bmp->data, encryptedData, dataSize);

    free(bmp->data);
    bmp->data = encryptedData;

    int result = writeBMPFile(outputFile, bmp);

    freeBMPImage(bmp);

    return result;
}

int encryptBMP_CBC(const char *inputFile, const char *outputFile, const uint8_t *key, const uint8_t *iv) {
    // Read the input BMP file
    BMPImage *bmp = readBMPFile(inputFile);
    if (!bmp) {
        fprintf(stderr, "Failed to read input BMP file\n");
        return EXIT_FAILURE;
    }

    // Setup DES key schedule
    deskeySchedule ks;
    keySchedule(&ks, key);

    // Calculate image data size
    size_t dataSize = bmp->infoHeader.imageSize;
    if (dataSize == 0) {
        int bytesPerPixel = bmp->infoHeader.bitsPerPixel / 8;
        if (bmp->infoHeader.bitsPerPixel % 8 != 0) bytesPerPixel++;

        int rowSize = (bmp->infoHeader.width * bytesPerPixel + 3) & ~3;
        dataSize = rowSize * abs(bmp->infoHeader.height);
    }

    // Allocate memory for encrypted data
    uint8_t *encryptedData = (uint8_t*)malloc(dataSize);
    if (!encryptedData) {
        fprintf(stderr, "Memory allocation for encrypted data failed\n");
        freeBMPImage(bmp);

        return EXIT_FAILURE;
    }

    // Encrypt the image data using CBC mode
    printf("CBC Mode: Encrypting %zu bytes of pixel data...\n", dataSize);
    cbcEncrypt(&ks, iv, bmp->data, encryptedData, dataSize);

    // Replace the original data with encrypted data
    free(bmp->data);
    bmp->data = encryptedData;

    // Write the encrypted BMP file
    int result = writeBMPFile(outputFile, bmp);

    // Clean up
    freeBMPImage(bmp);

    return result;
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: %s <bmp_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *inputFile = argv[1];
    const char *ecbOutput = "ecb_encrypted.bmp";
    const char *cbcOutput = "cbc_encrypted.bmp";

    uint8_t key[8];
    genrandomdesKey(key);

    uint8_t iv[8];
    genrandomIV(iv);

    printf("INPUT: %s\n\n", inputFile);

    printf("ENCRYPTION PARAMETERS:\n");
    printf("DES Key: ");
    printHex(key, 8);
    printf("IV (for CBC): ");
    printHex(iv, 8);
    printf("\n");

    printf("Encrypting using ECB mode...\n");
    if (encryptBMP_ECB(inputFile, ecbOutput, key)) {
        printf("Output saved to: %s\n", ecbOutput);
    } else {
        printf("ECB encryption failed\n");

        return EXIT_FAILURE;
    }

    printf("\nEncrypting using CBC mode...\n");
    if (encryptBMP_CBC(inputFile, cbcOutput, key, iv)) {
        printf("Output saved to: %s\n", cbcOutput);
    } else {
        printf("CBC encryption failed\n");

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}