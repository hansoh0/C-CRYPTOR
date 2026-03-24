#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>

#define AES_BLOCK_SIZE 16

long pad_length(long len);
int zero_file(const char *input_path, long filelen);

#endif 
