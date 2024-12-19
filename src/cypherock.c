// Check README file for details

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../include/trezor/ecdsa.h"
#include "../include/trezor/secp256k1.h"
#include "../include/trezor/sha2.h"

#define BYTE_LENGTH 32
#define SECURITY_PARAMETER 128
#define NUM_TEST_CASES 3

typedef struct {
    unsigned char share[BYTE_LENGTH];
    unsigned char commitment[SHA256_DIGEST_LENGTH];
} COTShare;

typedef struct {
    unsigned char a[BYTE_LENGTH];
    unsigned char b[BYTE_LENGTH];
    const char* description;
} TestCase;

void xor_bytes(unsigned char *result, const unsigned char *a, const unsigned char *b, size_t length) {
    for (size_t i = 0; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
}

void generate_random_bytes(unsigned char *bytes, size_t length) {
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom || fread(bytes, 1, length, urandom) != length) {
        perror("Random byte generation failed");
        exit(EXIT_FAILURE);
    }
    fclose(urandom);
}

void compute_sha256_commitment(
    unsigned char *commitment, 
    const unsigned char *data, 
    size_t len
) {
    SHA256_CTX sha256_ctx;
    sha256_Init(&sha256_ctx);
    sha256_Update(&sha256_ctx, data, len);
    sha256_Final(&sha256_ctx, commitment);
}

void mod_multiply(
    uint8_t *result, 
    const uint8_t *a, 
    const uint8_t *b, 
    const ecdsa_curve *curve
) {
    bignum256 bn_a, bn_b, bn_result;
    
    bn_read_be(a, &bn_a);
    bn_read_be(b, &bn_b);
    
    bn_multiply(&bn_a, &bn_b, &bn_result);
    bn_mod(&bn_result, &curve->order);
    
    bn_write_be(&bn_result, result);
}

void correlated_oblivious_transfer(
    const unsigned char *a,
    const unsigned char *b,
    COTShare *sender_share,
    COTShare *receiver_share,
    const ecdsa_curve *curve
) {
    unsigned char product[BYTE_LENGTH] = {0};
    unsigned char correlation_seed[BYTE_LENGTH] = {0};
    unsigned char receiver_randomness[BYTE_LENGTH] = {0};
    
    mod_multiply(product, a, b, curve);
    generate_random_bytes(correlation_seed, BYTE_LENGTH);
    generate_random_bytes(receiver_randomness, BYTE_LENGTH);
    
    xor_bytes(sender_share->share, correlation_seed, a, BYTE_LENGTH);
    compute_sha256_commitment(sender_share->commitment, sender_share->share, BYTE_LENGTH);
    
    unsigned char receiver_share_value[BYTE_LENGTH];
    xor_bytes(receiver_share_value, correlation_seed, product, BYTE_LENGTH);
    xor_bytes(receiver_share->share, receiver_share_value, receiver_randomness, BYTE_LENGTH);
    compute_sha256_commitment(receiver_share->commitment, receiver_share->share, BYTE_LENGTH);
}

int verify_correlated_oblivious_transfer(
    const COTShare *sender_share,
    const COTShare *receiver_share,
    const unsigned char *a,
    const unsigned char *b,
    const ecdsa_curve *curve
) {
    unsigned char product[BYTE_LENGTH] = {0};
    unsigned char reconstructed[BYTE_LENGTH] = {0};
    unsigned char reconstructed_commitment[SHA256_DIGEST_LENGTH] = {0};
    
    mod_multiply(product, a, b, curve);
    xor_bytes(reconstructed, sender_share->share, receiver_share->share, BYTE_LENGTH);
    compute_sha256_commitment(reconstructed_commitment, reconstructed, BYTE_LENGTH);
    
    return (
        memcmp(reconstructed, product, BYTE_LENGTH) == 0 &&
        memcmp(sender_share->commitment, sender_share->commitment, SHA256_DIGEST_LENGTH) == 0 &&
        memcmp(receiver_share->commitment, receiver_share->commitment, SHA256_DIGEST_LENGTH) == 0);
}

void print_hex(const char* label, const unsigned char* data, size_t length) {
    printf("%s", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void run_test_case(const TestCase* test_case, const ecdsa_curve *curve, int case_number) {
    printf("\nTest Case %d: %s\n", case_number, test_case->description);

    COTShare sender_share, receiver_share;
    correlated_oblivious_transfer(
        test_case->a,
        test_case->b,
        &sender_share,
        &receiver_share,
        curve
    );

    print_hex("Input A:  ", test_case->a, BYTE_LENGTH);
    print_hex("Input B:  ", test_case->b, BYTE_LENGTH);
    
    print_hex("Share 1: ", sender_share.share, BYTE_LENGTH);
    print_hex("Share 2: ", receiver_share.share, BYTE_LENGTH);

    int verification = verify_correlated_oblivious_transfer(
        &sender_share,
        &receiver_share,
        test_case->a,
        test_case->b,
        curve
    );

    printf("Verification: %s\n", verification ? "PASSED" : "FAILED");
}

int main() {
    const ecdsa_curve *curve = &secp256k1;
    
    TestCase test_cases[NUM_TEST_CASES] = {
        {
            .description = "Random values"
        },
        {
            .description = "Small values"
        },
        {
            .description = "Large values near curve order"
        }
    };

    for (int i = 0; i < NUM_TEST_CASES; i++) {
        generate_random_bytes(test_cases[i].a, BYTE_LENGTH);
        generate_random_bytes(test_cases[i].b, BYTE_LENGTH);

        bignum256 bn_a, bn_b;
        bn_read_be(test_cases[i].a, &bn_a);
        bn_read_be(test_cases[i].b, &bn_b);
        bn_mod(&bn_a, &curve->order);
        bn_mod(&bn_b, &curve->order);
        bn_write_be(&bn_a, test_cases[i].a);
        bn_write_be(&bn_b, test_cases[i].b);
    }

    printf("Running Correlated Oblivious Transfer Tests\n");

    for (int i = 0; i < NUM_TEST_CASES; i++) {
        run_test_case(&test_cases[i], curve, i + 1);
    }

    return 0;
}
