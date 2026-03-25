#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>

#define AES_BLOCK_SIZE 16

long pad_length(long len);
int zero_file(const char *input_path, long filelen);
int derive_key(const char *secret, const unsigned char *salt, unsigned char *key_out);
int encrypt_file(const char *input_path, const char *output_path, const unsigned char *key);


#endif 
