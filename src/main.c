#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define AES_BLOCK_SIZE 16
#define KEY_LEN 32
#define SALT_LEN 16
#define PBKDF2_ITR 100000

// Prototypes
unsigned char *encryptBuffer(unsigned char *buffer, long len, unsigned char *key, unsigned char *iv);
unsigned char *decryptBuffer(unsigned char *buffer, long len, unsigned char *key, unsigned char *iv);

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
 * usage():
 * Displays how to use the program
 */
static void usage(const char *prog) {
	fprintf(stderr,
			"Usage: %s <mode> <path> <secret> <salt>\n"
			" mode : encrypt | decrypt\n"
			" path : file or directory to encrypt\n"
			" secret : passphrase to encrypt/decrypt\n"
			" salt : salt to add to encryption (16 bytes)\n"
			"Example:\n"
			" %s encrypt ./docs secret 001256648903222efff0000000000000\n",
			prog,  prog);
}

/*
 * derive_key():
 * Derives a fixed length key from a user secret using PBKDF2
 * 
 * char secret: User supplied password
 * char salt: random salt
 * char key_out: derived key buffer 
 * 
 * salt mitigates rainbow table attacks, PBKDF2_ITR prevents brute force
 *
 * https://docs.openssl.org/3.0/man3/PKCS5_PBKDF2_HMAC/#name
 */
static int derive_key(const char *secret, const unsigned char *salt, unsigned char *key_out) {
       return PKCS5_PBKDF2_HMAC(secret, (int)strlen(secret), salt, SALT_LEN, PBKDF2_ITR, EVP_sha256(), KEY_LEN, key_out); 
}

/* Buffer encryption AES-256-CBC
 * Buffer is padded to AES_BLOCK_SIZE
 * IV is modified during this phase so storage of IV must happen before this
 * Returns a newly allocated buffer with encrypted data
 */
unsigned char *encryptBuffer(unsigned char *buffer, long len, unsigned char *key, unsigned char *iv) {
	AES_KEY aes_key;
	AES_set_encrypt_key(key, 256, &aes_key);
	unsigned char* encrypted_buffer = malloc(len);
	if (!encrypted_buffer) return NULL;
	AES_cbc_encrypt(buffer, encrypted_buffer, len, &aes_key, iv, AES_ENCRYPT);
	return encrypted_buffer;
}

/* Buffer decryption AES-256-CBC
 * Buffer padding is not removed after decryption which could cause trailing bytes
 * No authentication used to thwart tampering (CBC)
 * Iv is modified during this phase
 * This is NOT secure, only PoC
 * Returns a newly alllocated buffer with decrypted data.
 */
unsigned char *decryptBuffer(unsigned char *buffer, long len, unsigned char *key, unsigned char *iv) {
	AES_KEY aes_key;
	AES_set_decrypt_key(key, 256, &aes_key);
	unsigned char *decrypted_buffer = malloc(len);
	if (!decrypted_buffer) return NULL;
	AES_cbc_encrypt(buffer, decrypted_buffer, len, &aes_key, iv, AES_DECRYPT);
	return decrypted_buffer;
}

int main(int argc, char *argv[]) {
}
