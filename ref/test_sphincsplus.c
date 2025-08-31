#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "api.h"
#include "randombytes.h"

#define MLEN 1200 // limit input for testing
#define NTESTS 1 // test count

void run_test(FILE *fout, const unsigned char *m, unsigned long long mlen, int test_idx) {
    // KeyGen
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    fprintf(fout, "Test #%d\n", test_idx+1);
    fprintf(fout, "KeyGen Stage:\n- Input: None\n- Output:\n");

    fprintf(fout, "* Public Key: ");
    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) fprintf(fout, "%02x", pk[i]);
    fprintf(fout, "\n* Secret Key: ");
    for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) fprintf(fout, "%02x", sk[i]);
    fprintf(fout, "\n\n");

    // Signing
    unsigned char sm[MLEN + CRYPTO_BYTES];
    unsigned long long smlen = 0;
    crypto_sign(sm, &smlen, m, mlen, sk);

    fprintf(fout, "Signing Stage:\n- Input: input.txt, sk\n- Output:\n");

    fprintf(fout, "* Signed Message: ");
    for (unsigned long long i = 0; i < smlen; i++) fprintf(fout, "%02x", sm[i]);
    fprintf(fout, "\n\n");

    // Open/Verify
    unsigned char m2[MLEN + CRYPTO_BYTES] = {0};
    unsigned long long m2len = 0;
    int valid = crypto_sign_open(m2, &m2len, sm, smlen, pk);
    fprintf(fout, "Verifying Stage:\n- Input: signed message, pk\n- Output: %s\n", valid == 0 ? "Valid" : "Invalid");
    if (!valid) {
        fprintf(fout, "* Opened Message: ");
        for (unsigned long long i = 0; i < m2len; i++) fprintf(fout, "%02x", m2[i]);
        fprintf(fout, "\n");
    }
    fprintf(fout, "\n");
}

int main(void) {
    FILE *fin = fopen("input.txt", "rb");
    FILE *fout = fopen("output.txt", "w");
    if (!fin || !fout) {
        printf("File error\n");
        return 1;
    }

    // Read message from input.txt only once
    unsigned char m[MLEN + CRYPTO_BYTES] = {0};
    unsigned long long mlen = fread(m, 1, MLEN, fin);
    fclose(fin);

    for (int test = 0; test < NTESTS; ++test) {
        run_test(fout, m, mlen, test);
    }
    fclose(fout);

    // Print testing information
    printf("\n[Testing Information - %d runs]\n\n", NTESTS);
    printf("Public key bytes = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("Secret key bytes = %d\n", CRYPTO_SECRETKEYBYTES);
    printf("Signature bytes = %d\n", CRYPTO_BYTES);

    return 0;
}
