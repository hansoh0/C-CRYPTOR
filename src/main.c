#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define AES_BLOCK_SIZE 16

// Prototypes
unsigned char *encryptBuffer(unsigned char *buffer, long filelen, unsigned char *userKey, unsigned char *iv);
unsigned char *decryptBuffer(unsigned char *buffer, long filelen, unsigned char *userKey, unsigned char *iv);

/* Returns the required buffer size for proper AES-CBC encryption by calculating the smalles multiple of AES_BLOCK_SIZE that can fit
 * len which is the length of the buffer to be encrypted.
 *
 * This is not a padding scheme implementation -> NOT PKCS#7
 * The buffer is zero padded via calloc -> ie. if buffer is 15 bytes, the 16th byte would be 0x00
 * -> zero padding means if last byte in data is 0x00, after decryption the end is mixed with the zero padding
 * -> ie. [01 02 03 04 05 06 07 08 09 0a 0b 0c 0e 0f 00](15 bytes) + [00](padding)
 * -> decrypted as: [01 02 03 04 05 06 07 08 09 0a 0b 0c 0e 0f 00 00] <- ambiguous
 */
long pad_length(long len) {
        return ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
}

/*
 * Program to test encryption/decryption of a specified file.
 *
 * This is a proof of concept skeleton not to be used in production.
 *
 * 1. Defines a file test/file.txt
 * 2. Allows user to supply key
 * 3. Encrypts file as a binary buffer & writes out with IV
 *  OUT (test/file.enc) -> [16 Byte IV][ENCRYPED BUFFER]
 * 4. Reads test/file.enc as binary buffer
 * 5. Parses IV to use for decryption
 * 6. Decrypts buffer and writes out as decrypted binary buffer
 *  OUT (test/file.dec) -> [DECRYPTED_TEXT]
 */
int main() {
        // Target file to encrypt decrypt
        const char filename[] = "test/file.txt";
        FILE *fileptr;
        unsigned char* buffer;
        long filelen;

        /*
         * Takes key from user.
         * This uses raw input - in prod KDF should be used.
         * This is NOT secure, only PoC.
         */
        unsigned char userKey[32];
        char input[64];
        printf("Enter key: ");
        fgets(input, sizeof(input), stdin);
        memset(userKey, 0, 32);
        memcpy(userKey, input, strlen(input) > 32 ? 32 : strlen(input));

        // Open File as binary data
        fileptr = fopen(filename, "rb");
        if (fileptr == NULL)
        {
                fprintf(stderr, "Error reading from %s\n", filename);
                return 1;
        }

        // Retreive file size
        fseek(fileptr, 0, SEEK_END);
        filelen = ftell(fileptr);
        rewind(fileptr);

        // Allocate memory for 1 byte per char
        long padded_len = pad_length(filelen);
        buffer = calloc(padded_len, 1);
        if (buffer == NULL) {
                fclose(fileptr);
                return 1;
        }

        // Read file into buffer 1 byte per char
        fread(buffer, 1, filelen, fileptr);

        // Close file
        fclose(fileptr);

        // Generatie IV
        unsigned char iv[AES_BLOCK_SIZE];
        RAND_bytes(iv, AES_BLOCK_SIZE);

        // Copy unmutated IV for storage
        unsigned char iv_enc[AES_BLOCK_SIZE];
        memcpy(iv_enc, iv, AES_BLOCK_SIZE);

        // Encrypt buffer
        unsigned char *encrypted_buffer = encryptBuffer(buffer, padded_len, userKey, iv_enc);

        // Open file for writing encrypted text
        FILE *encfp_wb = fopen("test/file.enc", "wb");
        if (encfp_wb == NULL) {
                perror("Error Opening File");
                return 1;
        }

        // Write IV to the first 16 bytes, then write encryped text
        fwrite(iv, 1, AES_BLOCK_SIZE, encfp_wb);
        fwrite(encrypted_buffer, 1, padded_len, encfp_wb);
        fclose(encfp_wb);


        // Open file for reading encrypted text
        FILE *encfp_rb = fopen("test/file.enc", "rb");
        if (encfp_rb == NULL) return 1;

        // Read IV from first 16 bytes of the file
        unsigned char read_iv[AES_BLOCK_SIZE];
        fread(read_iv, 1, AES_BLOCK_SIZE, encfp_rb);

        // Read encrypted text from file
        unsigned char *enc_input = malloc(padded_len);
        fread(enc_input, 1, padded_len, encfp_rb);
        fclose(encfp_rb);

        // Decrypt encrypted buffer
        unsigned char *decrypted_buffer = decryptBuffer(enc_input, padded_len, userKey, read_iv);

        // Open file for writing decrypted text
        FILE *decfp_wb = fopen("test/file.dec", "wb");
        fwrite(decrypted_buffer, 1, padded_len, decfp_wb);
        fclose(decfp_wb);

        // Free all allocated memory
        free(buffer);
        free(encrypted_buffer);
        free(enc_input);
        free(decrypted_buffer);

        return 0;
}

/* Buffer encryption AES-256-CBC
 * Buffer is padded to AES_BLOCK_SIZE
 * IV is modified during this phase so storage of IV must happen before this
 * Returns a newly allocated buffer with encrypted data
 */
unsigned char *encryptBuffer(unsigned char *buffer, long filelen, unsigned char *userKey, unsigned char *iv) {
        AES_KEY aes_key;
        AES_set_encrypt_key(userKey, 256, &aes_key);
        unsigned char* encrypted_buffer = malloc(filelen);
        AES_cbc_encrypt(buffer, encrypted_buffer, filelen, &aes_key, iv, AES_ENCRYPT);
        return encrypted_buffer;
}

/* Buffer decryption AES-256-CBC
 * Buffer padding is not removed after decryption which could cause trailing bytes
 * No authentication used to thwart tampering (CBC)
 * Iv is modified during this phase
 * This is NOT secure, only PoC
 * Returns a newly alllocated buffer with decrypted data.
 */
unsigned char *decryptBuffer(unsigned char *buffer, long filelen, unsigned char *userKey, unsigned char *iv) {
        AES_KEY aes_key;
        AES_set_decrypt_key(userKey, 256, &aes_key);
        unsigned char *decrypted_buffer = malloc(filelen);
        AES_cbc_encrypt(buffer, decrypted_buffer, filelen, &aes_key, iv, AES_DECRYPT);
        return decrypted_buffer;
}

