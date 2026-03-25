#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "crypt.h"

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

/*
 * Structure that holds an array of file paths, how many paths are stored, and how many paths can be held before growth
 */
typedef struct {
	char **paths;
	int count;
	int capacity;
} FileList;

/*
 * Initializes the list with a capacity of 64 paths, 
 * 0 paths in the list, and the allocated memory for the array of thats is the
 * size of 64 distinct pointers (the malloc is confirmed by returning 0(success) or -1(failure)
 */
static int fl_init(FileList *fl) {
	fl->capacity = 64;
	fl->count = 0;
	fl->paths = malloc(fl->capacity * sizeof(char *));
	return fl->paths ? 0 : -1;
}

/*
 * fl_push():
 * Adds a new path the the list
 * if capacity is met, increase capacity by doubling it, 
 * resize the memory allocation of the array while maintaining element by
 * reallocating memory to be the capacity * 1 pointer, 
 * if the realloc fails return -1, finallys updates the fl pointer to new memory
 *
 * Copy string into heap, and allocate memory for that string, if failed, return -1. 
 * Update count to account for one more element
 * added. Return 0 for success.
 */
static int fl_push(FileList *fl, const char *path) {
	if (fl->count == fl->capacity) {
		fl->capacity *= 2;
		char **tmp = realloc(fl->paths, fl->capacity * sizeof(char *));
		if (!tmp) return -1;
		fl->paths = tmp;
	}
	fl->paths[fl->count] = strdup(path);
	if (!fl->paths[fl->count]) return -1;
	fl->count++;
	return 0;
}

/*
 * fl_free():
 * Cleanup file list
 * Free element 1 by 1 in paths,
 * then free the defined (now empty) array and update count and capacity to 0.
 * Resets FileList structure
 */
static void fl_free(FileList *fl) {
	for (int i = 0; i < fl->count; i++) free(fl->paths[i]);
	free(fl->paths);
	fl->count = fl->capacity = 0;
}

/*
 * walk():
 * Recursively walks a directory tree and collects file paths
 *
 * First it opens the directory and represents each item inside as a structure
 * then the full path is stored
 *
 * then ewe loop through each entry in the specified directory, skipping . and ..
 * for the remaining elements it builds the full location path of those elements relative to the base_path
 * then it checks for encoding errors or if the path is too long and skips them
 *
 * continuing the structure stat holds information long listed from the file - dir or file, permissions, size
 * if its a directory (st.st_mode ISDIR), recurse,
 * else, add it to the list of files
 *
 * at the end close the directory and return 0
 */
static int walk(const char *start_path, FileList *fl) {
	DIR *dir = opendir(start_path);
	if (!dir) {
		perror(start_path);
		return -1;
	}

	struct dirent *entry;
	char path[MAX_PATH];

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

		int n = snprintf(path, sizeof(path), "%s/%s", start_path, entry->d_name);
		if (n < 0 || n >= (int)sizeof(path)) {
			fprintf(stderr, "Path too long, skipping: %s/%s\n", start_path, entry->d_name);
			continue;
		}

		struct stat st;
		if (stat(path, &st) != 0) {
			perror(path);
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			if (walk(path, fl) != 0) {
				closedir(dir);
				return -1;
			}
		} else if (S_ISREG(st.st_mode)) {
			if (fl_push(fl, path) != 0) {
				closedir(dir);
				return -1;
			}
		}
	}
	closedir(dir);
	return 0;
}

/*
 * collect_files():
 * Adds full path of file to FileList
 * If directory, it drills down
 */
static int collect_files(const char *path, FileList *fl) {
	struct stat st;
	if (stat(path, &st) != 0) {
		perror(path);
		return -1;
	}

	if (S_ISREG(st.st_mode)) {
		return fl_push(fl, path);
	} else if (S_ISDIR(st.st_mode)) {
		return walk(path, fl);
	}

	fprintf(stderr, "%s is not a file or directory\n", path);
	return -1;
}

/*
 * build_output_path():
 * 
 * char input_path: path to the input file
 * int encrypt: encrypt/decrypt mode
 * char output_path: buffer to store resulting path
 * size_t output_size: the buffer size of output_path
 *
 * builds the full path of the output file for writing
 * returns 0 on success, -1 on error
 */
static int build_output_path(const char *input_path, int encrypt, char *output_path, size_t output_size) {
	if (encrypt) {
		int n = snprintf(output_path, output_size, "%s.enc", input_path);
		return (n > 0 && (size_t)n < output_size) ? 0 : -1;
	} else {
		size_t len = strlen(input_path);
		if(len < 4 || strcmp(input_path + len -4, ".enc") != 0) {
			fprintf(stderr, "Skipping %s: does not end with .enc\n", input_path);
			return -1;
		}
		int n = snprintf(output_path, output_size, "%.*s", (int)(len - 4), input_path);
		return (n > 0 && (size_t)n < output_size) ? 0 : -1;
	}
}

/*
 * get_salt():
 * char hex: the hexedecimal string to be used to generate a salt
 * char salt: the outputted salt created from the hex input
 * 
 * converts 32-character hex string to 16-byte salt.
 * helps prevent rainbow table attacks
 * returns 0 on success, -1 on error
 */
static int get_salt(const char *hex, unsigned char *salt) {
	if (strlen(hex) != 32) {
		return -1;
	}
	for (int i = 0; i < 16; i++) {
		unsigned int byte;
		if (sscanf(hex + 2 * i, "%02x", &byte) != 1) {
			return -1;
		}
		salt[i] = (unsigned char)byte;
	}
	return 0;
}

/*
 * zero_file();
 * char input_path: the path of the file thats going to be zero'd and removed
 * long filelen: the length of input_path file
 * 
 * replaces bytes in given file with all zeros & deletes it from filesystem
 * thwarts forensic attempts to recover the original file
 */
static int zero_file(const char *input_path, long filelen) {
	FILE *fp = fopen(input_path, "r+b");
	if (!fp) return -1;
		
	// Write zeros over entire file contents
	unsigned char zero_buf[4096] = {0};
	long therest = filelen;
	while (therest > 0) {
		// Set to_write to the remaining amount of bytes (therest) or buffer size of zero_buff, whichever is smaller
		long to_write = therest < (long)sizeof(zero_buf) ? therest : (long)sizeof(zero_buf);
		if (fwrite(zero_buf, 1, to_write, fp) != (size_t)to_write) {
			fprintf(stderr, "Write error while zeroing %s\n", input_path);
			fclose(fp);
			return -1;
		}
		therest -= to_write;
	}
	
	fflush(fp);
	fclose(fp);
	
	if (remove(input_path) != 0) {
		perror(input_path);
		return -1;
	}
	return 0;
}

/*
 * encrypt_file():
 * 
 * char input_path: path of the file to encrypt
 * char output_path: path of the file where encrypted output will be written
 * char key: derived key for encryption
 *
 * encrypts a given file by loading its contents into a buffer,
 * fully removes input_path from the filesystem
 * encrypting that buffer with encryptBuffer(),
 * then writing out to specified output_path with [16 byte IV][8 byte little-endian encoded length of file][encrypted data]
 */
static int encrypt_file(const char *input_path, const char *output_path, const unsigned char *key) {
	// Open file as binary data
	FILE *fp = fopen(input_path, "rb");
	if (!fp) { 
		perror(input_path);
		return -1;
	}

	// Retrieve file size
	fseek(fp, 0, SEEK_END);
	long filelen = ftell(fp);
	rewind(fp);

	// Allocate memory for 1 byte per char
	long padded_len = pad_length(filelen);
	unsigned char *buffer = calloc(padded_len, 1);
	if (!buffer) {
		fclose(fp);
		return -1;
	}

	// Read file into buffer 1 byte per char, close file
	fread(buffer, 1, filelen, fp);
	fclose(fp);

	zero_file(input_path, filelen);

	// Generate IV
	unsigned char iv[AES_BLOCK_SIZE];
	RAND_bytes(iv, AES_BLOCK_SIZE);

	// Copy iv and prepare for plant
	unsigned char iv_copy[AES_BLOCK_SIZE];
	memcpy(iv_copy, iv, AES_BLOCK_SIZE);

	// Encrypt buffer
	unsigned char *encbuff = encryptBuffer(buffer, padded_len, key, iv_copy);
	if (!encbuff) {
		return -1;
	}

	// Free original buffer memory
	free(buffer);

	// Open output file
	FILE *out = fopen(output_path, "wb");
	if (!out) {
		perror(output_path);
		free(encbuff);
		return -1;
	}

	// Write out IV
	fwrite(iv, 1, AES_BLOCK_SIZE, out);

	// Write original length of file little-endian
	unsigned char len_bytes[8];
	long tmp = filelen;
	for (int i = 0; i < 8; i++) {
		len_bytes[i] = tmp & 0xFF;
		tmp >>= 8;
	}
	fwrite(len_bytes, 1, 8, out);

	// Write encrypted buffer
	fwrite(encbuff, 1, padded_len, out);
	fclose(out);
	free(encbuff);
	return 0;
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
