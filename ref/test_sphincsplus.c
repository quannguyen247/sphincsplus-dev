// test_sphincsplus.c - Generate SPHINCS+ keypair, sign and verify, message from input.txt
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "randombytes.h"

void fprintBstr(FILE *fp, const char *S, const unsigned char *A, unsigned long long L);

int main(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char msg[3300];
    unsigned long long mlen = 0;
    FILE *fp = fopen("input.txt", "rb");
    if (fp == NULL) {
        printf("Could not open input.txt\n");
        return 1;
    }
    mlen = fread(msg, 1, sizeof(msg), fp);
    fclose(fp);

    unsigned char sm[CRYPTO_BYTES + sizeof(msg)];
    unsigned long long smlen;
    unsigned char m1[CRYPTO_BYTES + sizeof(msg)];
    unsigned long long mlen1;

    crypto_sign_keypair(pk, sk);
    crypto_sign(sm, &smlen, msg, mlen, sk);
    int valid = (crypto_sign_open(m1, &mlen1, sm, smlen, pk) == 0 && mlen1 == mlen && memcmp(msg, m1, mlen) == 0);

    FILE *fp_out = fopen("output.txt", "w");
    if (fp_out) {
        // Key Generation Stage
        fprintf(fp_out, "Key Generation Stage:\n");
        fprintf(fp_out, " - Input: None\n");
        fprintf(fp_out, " - Output:\n");
        fprintBstr(fp_out, "* Public Key: ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp_out, "* Secret Key: ", sk, CRYPTO_SECRETKEYBYTES);
        fprintf(fp_out, "\n");

        // Signing Stage
        fprintf(fp_out, "Signing Stage:\n");
        fprintf(fp_out, " - Input: input.txt, sk\n");
        fprintf(fp_out, " - Output:\n");
        fprintBstr(fp_out, "* Signature: ", sm, CRYPTO_BYTES);
        fprintf(fp_out, "\n");

        // Verifying Stage
        fprintf(fp_out, "Verifying Stage:\n");
        fprintf(fp_out, " - Input: input.txt, sig, pk\n");
        fprintf(fp_out, " - Output: %s\n", valid ? "Valid" : "Invalid");
        fclose(fp_out);
    }
    return 0;
}

void fprintBstr(FILE *fp, const char *S, const unsigned char *A, unsigned long long L) {
    fprintf(fp, "%s", S);
    for (unsigned long long i = 0; i < L; i++)
        fprintf(fp, "%02X", A[i]);
    if (L == 0) fprintf(fp, "00");
    fprintf(fp, "\n");
}
