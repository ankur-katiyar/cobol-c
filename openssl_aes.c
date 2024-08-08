// openssl_aes.c
// Author - Ankur Katiyar

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

// Initialize encryption and decryption contexts
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
    int i, nrounds = 5;
    unsigned char key[32], iv[32];

    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 32) {
        printf("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    return 0;
}

// Encrypts the plaintext
unsigned char* aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len) {
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = malloc(c_len);

    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
    EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

    *len = c_len + f_len;

    // Convert the ciphertext to a numeric string of the same length as plaintext
    char *numeric_ciphertext = malloc(*len + 1);
    for (int i = 0; i < *len; i++) {
        numeric_ciphertext[i] = (ciphertext[i] % 10) + '0'; // Mod 10 and convert to digit character
    }
    numeric_ciphertext[*len] = '\0';

    free(ciphertext);
    return numeric_ciphertext;
}

// Decrypts the ciphertext
unsigned char* aes_decrypt(EVP_CIPHER_CTX *d, unsigned char *numeric_ciphertext, int *len) {
    int p_len = *len, f_len = 0;
    unsigned char *ciphertext = malloc(p_len);

    // Convert numeric string back to original ciphertext
    for (int i = 0; i < *len; i++) {
        ciphertext[i] = numeric_ciphertext[i] - '0'; // Convert digit character back to byte
    }

    unsigned char *plaintext = malloc(p_len);
    EVP_DecryptInit_ex(d, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(d, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(d, plaintext + p_len, &f_len);

    *len = p_len + f_len;
    free(ciphertext);
    return plaintext;
}

// Cleanup encryption and decryption contexts
void aes_cleanup(EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
    EVP_CIPHER_CTX_cleanup(e_ctx);
    EVP_CIPHER_CTX_cleanup(d_ctx);
}

// Base64 encoding function
int base64_encode(const unsigned char *input, int length, char *output) {
    EVP_ENCODE_CTX ctx;
    int output_length = 0;
    int temp_length = 0;

    EVP_EncodeInit(&ctx);
    EVP_EncodeUpdate(&ctx, (unsigned char*)output, &temp_length, input, length);
    output_length += temp_length;
    EVP_EncodeFinal(&ctx, (unsigned char*)(output + temp_length), &temp_length);
    output_length += temp_length;

    return output_length;
}

// Base64 decoding function
int base64_decode(const char *input, int length, unsigned char *output) {
    EVP_ENCODE_CTX ctx;
    int output_length = 0;
    int temp_length = 0;
    int ret;

    EVP_DecodeInit(&ctx);
    ret = EVP_DecodeUpdate(&ctx, output, &temp_length, (const unsigned char*)input, length);
    if (ret < 0) {
        return ret;  // Error in decoding
    }
    output_length += temp_length;
    ret = EVP_DecodeFinal(&ctx, output + temp_length, &temp_length);
    if (ret < 0) {
        return ret;  // Error in decoding
    }
    output_length += temp_length;

    return output_length;
}


// Example usage
int main() {
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; // 32 bytes key for AES-256
    unsigned char *iv = (unsigned char *)"0123456789012345"; // 16 bytes IV for AES
    unsigned char *salt = (unsigned char *)"12345678"; // 8 bytes salt for key generation

    char *plaintext = "HelloWorld123456";
    int len = strlen(plaintext);

    EVP_CIPHER_CTX en, de;
    aes_init(key, strlen((char*)key), salt, &en, &de);

    // Encrypt
    unsigned char *ciphertext = aes_encrypt(&en, (unsigned char *)plaintext, &len);
    printf("Encrypted (numeric): %s\n", ciphertext);

    // Decrypt
    unsigned char *decryptedtext = aes_decrypt(&de, ciphertext, &len);
    printf("Decrypted: %s\n", decryptedtext);

    aes_cleanup(&en, &de);

    free(ciphertext);
    free(decryptedtext);

    return 0;
}
