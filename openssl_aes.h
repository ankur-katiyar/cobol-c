// openssl_aes.h

#ifndef OPENSSL_AES_H
#define OPENSSL_AES_H

#include <openssl/evp.h>

// Function to initialize the AES context
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);

// Function to encrypt data
unsigned char* aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);

// Function to decrypt data
unsigned char* aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);

// Function to clean up AES context
void aes_cleanup(EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);


// Function to encode data to Base64
int base64_encode(const unsigned char *input, int length, char *output);

// Function to decode Base64 encoded data
int base64_decode(const char *input, int length, unsigned char *output);

#endif // OPENSSL_AES_H
