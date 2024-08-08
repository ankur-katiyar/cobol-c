#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

// Function to initialize AES context
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
    int i;
    unsigned char key[32], iv[32];

    i = EVP_BytesToKey(EVP_aes_256_ctr(), EVP_sha1(), salt, key_data, key_data_len, 1, key, iv);
    if (i != 32) {
        printf("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_ctr(), NULL, key, iv);

    return 0;
}

// Function to convert binary data to a hexadecimal string
void bin_to_hex(const unsigned char *bin, int len, char *hex) {
    for (int i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

// Function to convert a hexadecimal string to binary data
void hex_to_bin(const char *hex, unsigned char *bin) {
    for (int i = 0; i < strlen(hex) / 2; i++) {
        sscanf(hex + (i * 2), "%02x", &bin[i]);
    }
}

// Function to encrypt plaintext and return as a hexadecimal string
char* aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len) {
    int c_len = *len, f_len = 0;
    unsigned char *ciphertext = malloc(c_len + AES_BLOCK_SIZE);

    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
    EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

    // Convert the binary ciphertext to a hexadecimal string
    char *hex_ciphertext = malloc((c_len + f_len) * 2 + 1);
    bin_to_hex(ciphertext, c_len + f_len, hex_ciphertext);

    free(ciphertext);
    *len = (c_len + f_len) * 2;  // Update length to reflect the hex string length
    return hex_ciphertext;
}

// Function to decrypt a hexadecimal string back to plaintext
unsigned char* aes_decrypt(EVP_CIPHER_CTX *d, const char *hex_ciphertext, int *len) {
    int bin_len = *len / 2;
    unsigned char *ciphertext = malloc(bin_len);
    unsigned char *plaintext = malloc(bin_len);

    // Convert the hexadecimal string back to binary data
    hex_to_bin(hex_ciphertext, ciphertext);

    EVP_DecryptInit_ex(d, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(d, plaintext, &bin_len, ciphertext, bin_len);

    int f_len = 0;
    if (!EVP_DecryptFinal_ex(d, plaintext + bin_len, &f_len)) {
        printf("Decryption failed.\n");
    }

    *len = bin_len + f_len;
    plaintext[*len] = '\0';  // Null-terminate the plaintext

    free(ciphertext);
    return plaintext;
}

// Cleanup function to free the context
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

// Main function for testing
int main() {
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; // 32 bytes key for AES-256
    unsigned char *salt = (unsigned char *)"12345678"; // 8 bytes salt for key generation

    char *plaintext = "SG8Vy4jBJP";  // Example input string
    int len = strlen(plaintext);

    EVP_CIPHER_CTX en, de;
    aes_init(key, strlen((char*)key), salt, &en, &de);

    // Encrypt
    char *ciphertext = aes_encrypt(&en, (unsigned char *)plaintext, &len);
    printf("Encrypted (hex): %s\n", ciphertext);

    // Decrypt
    len = strlen(ciphertext);  // Reset the length to the size of the hex string
    unsigned char *decryptedtext = aes_decrypt(&de, ciphertext, &len);
    printf("Decrypted: %s\n", decryptedtext);

    aes_cleanup(&en, &de);

    free(ciphertext);
    free(decryptedtext);

    return 0;
}


