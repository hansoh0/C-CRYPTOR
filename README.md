A file & directory encryptor written in C. This cryptor uses AES256 and encrypts files by bytes, allowing for encryption of many different types of files. created by @hansoh0 (https://www.github.com/hansoh0)

# Compiling & Running
## Compiling/Running the Cryptor
```
$> make
$> ./cryto 
Usage: ./crypto <mode> <path> <secret> <salt>
 mode : encrypt | decrypt
 path : file or directory to encrypt
 secret : passphrase to encrypt/decrypt
 salt : salt to add to encryption (16 bytes)
Example:
 ./crypto encrypt ./docs secret 001256648903222efff0000000000000
```
## Compiling/Running the Tests
```
$> make test
[Warning & Cunit Copyright Output Omitted]

Suite: pad_length
  Test: sizes ...passed
Suite: zero_file
  Test: removes file ...passed
  Test: empty file ...passed
  Test: no path ...passed

Run Summary:    Type  Total    Ran Passed Failed Inactive
              suites      2      2    n/a      0        0
               tests      4      4      4      0        0
             asserts     10     10     10      0      n/a

Elapsed time =    0.000 seconds
```

WORK IN PROGRESS
