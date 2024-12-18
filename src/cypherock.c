#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../include/trezor/ecdsa.h"
#include "../include/trezor/secp256k1.h"
#include "../include/trezor/sha2.h" 


// Constant definitions
#define BYTE_LENGTH 32

// Struct to represent a share
typedef struct {
    unsigned char share[BYTE_LENGTH];
} Share;

// XOR function for byte arrays
void xor_bytes(unsigned char *result, const unsigned char *a, const unsigned char *b, size_t length) {
    for (size_t i = 0; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
}

// Generate random bytes securely
void generate_random_bytes(unsigned char *bytes, size_t length) {
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom || fread(bytes, 1, length, urandom) != length) {
        perror("Random byte generation failed");
        exit(EXIT_FAILURE);
    }
    fclose(urandom);
}

// Modular multiplication of a and b under curve's finite field order
void mod_multiply(uint8_t *result, const uint8_t *a, const uint8_t *b, const ecdsa_curve *curve) {
    bignum256 bn_a, bn_b, bn_result;
    
    // Convert input bytes to bignums
    bn_read_be(a, &bn_a);
    bn_read_be(b, &bn_b);
    
    // Perform modular multiplication
    bn_multiply(&bn_a, &bn_b, &bn_result);
    
    // Ensure result is within the field order
    bn_mod(&bn_result, &curve->order);
    
    // Write result back to byte array
    bn_write_be(&bn_result, result);
}

// Generate additive shares of the product under the finite field
void generate_additive_shares(
    Share *share1, 
    Share *share2, 
    const unsigned char *a, 
    const unsigned char *b, 
    const ecdsa_curve *curve
) {
    unsigned char product[BYTE_LENGTH] = {0};
    
    // Compute product = (a * b) mod curve->order
    mod_multiply(product, a, b, curve);
    
    // Generate random share and compute the complementary share
    generate_random_bytes(share1->share, BYTE_LENGTH);
    xor_bytes(share2->share, product, share1->share, BYTE_LENGTH);
}

// Validate shares: share1 XOR share2 == (a * b) mod field order
int validate_shares(
    const Share *share1, 
    const Share *share2, 
    const unsigned char *a, 
    const unsigned char *b, 
    const ecdsa_curve *curve
) {
    unsigned char reconstructed[BYTE_LENGTH] = {0};
    unsigned char expected[BYTE_LENGTH] = {0};
    
    // Reconstruct by XOR'ing shares
    xor_bytes(reconstructed, share1->share, share2->share, BYTE_LENGTH);
    
    // Compute expected product
    mod_multiply(expected, a, b, curve);
    
    // Compare the results
    return (memcmp(reconstructed, expected, BYTE_LENGTH) == 0);
}

// Optional: SHA256 hash verification for additional security
void compute_sha256(
    unsigned char *hash, 
    const unsigned char *data, 
    size_t len
) {
    SHA256_CTX sha256_ctx;
    sha256_Init(&sha256_ctx);
    sha256_Update(&sha256_ctx, data, len);
    sha256_Final(&sha256_ctx, hash);
}

int main() {
    const ecdsa_curve *curve = &secp256k1; // Use secp256k1 curve
    
    // Generate two random 32-byte numbers
    unsigned char a[BYTE_LENGTH], b[BYTE_LENGTH];
    generate_random_bytes(a, BYTE_LENGTH);
    generate_random_bytes(b, BYTE_LENGTH);
    
    printf("Random Number A: ");
    for (int i = 0; i < BYTE_LENGTH; i++) printf("%02x", a[i]);
    printf("\n");
    
    printf("Random Number B: ");
    for (int i = 0; i < BYTE_LENGTH; i++) printf("%02x", b[i]);
    printf("\n");
    
    // Generate shares
    Share share1, share2;
    generate_additive_shares(&share1, &share2, a, b, curve);
    
    printf("Share 1: ");
    for (int i = 0; i < BYTE_LENGTH; i++) printf("%02x", share1.share[i]);
    printf("\n");
    
    printf("Share 2: ");
    for (int i = 0; i < BYTE_LENGTH; i++) printf("%02x", share2.share[i]);
    printf("\n");
    
    // Optional: SHA256 hash verification
    unsigned char hash_a[SHA256_DIGEST_LENGTH];
    unsigned char hash_b[SHA256_DIGEST_LENGTH];
    unsigned char hash_share1[SHA256_DIGEST_LENGTH];
    unsigned char hash_share2[SHA256_DIGEST_LENGTH];
    
    compute_sha256(hash_a, a, BYTE_LENGTH);
    compute_sha256(hash_b, b, BYTE_LENGTH);
    compute_sha256(hash_share1, share1.share, BYTE_LENGTH);
    compute_sha256(hash_share2, share2.share, BYTE_LENGTH);
    
    printf("SHA256 Hash of A:       ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", hash_a[i]);
    printf("\nSHA256 Hash of B:       ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", hash_b[i]);
    printf("\nSHA256 Hash of Share 1: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", hash_share1[i]);
    printf("\nSHA256 Hash of Share 2: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", hash_share2[i]);
    printf("\n");
    
    // Validate shares
    if (validate_shares(&share1, &share2, a, b, curve)) {
        printf("Shares are valid: a * b = share1 + share2 under the finite field.\n");
    } else {
        printf("Share validation failed!\n");
    }
    
    return 0;
}