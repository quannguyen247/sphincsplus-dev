// test_sphincsplus.c - Generate SPHINCS+ keypair, sign and verify, message from input.txt
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "api.h"
#include "randombytes.h"

void fprintBstr(FILE *fp, const char *S, const unsigned char *A, unsigned long long L);

int main(void) {
    clock_t keygen_start, keygen_end, sign_start, sign_end, verify_start, verify_end;
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

    keygen_start = clock();
    crypto_sign_keypair(pk, sk);
    keygen_end = clock();

    // Uncomment the next line to make the secret key invalid for testing
    // sk[0] ^= 0xFF;

    sign_start = clock();
    crypto_sign(sm, &smlen, msg, mlen, sk);
    sign_end = clock();

    // Uncomment the next line to make the signature invalid for testing
    // sm[0] ^= 0xFF;

    verify_start = clock();
    int valid = (crypto_sign_open(m1, &mlen1, sm, smlen, pk) == 0 && mlen1 == mlen && memcmp(msg, m1, mlen) == 0);
    verify_end = clock();
    
    double keygen_time = (double)(keygen_end - keygen_start) / CLOCKS_PER_SEC;
    double sign_time = (double)(sign_end - sign_start) / CLOCKS_PER_SEC;
    double verify_time = (double)(verify_end - verify_start) / CLOCKS_PER_SEC;
    double total_time = (double)(keygen_time + sign_time + verify_time);

    FILE *fp_out = fopen("output.txt", "w");
    if (fp_out) {
        // Key Generation Stage
        fprintf(fp_out, "Key Generation Stage:\n");
        fprintf(fp_out, "- Input: None\n");
        fprintf(fp_out, "- Output:\n");
        fprintBstr(fp_out, "* Public Key: ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp_out, "* Secret Key: ", sk, CRYPTO_SECRETKEYBYTES);
        fprintf(fp_out, "* Time: %.6f seconds\n", keygen_time);
        fprintf(fp_out, "\n");

        // Signing Stage
        fprintf(fp_out, "Signing Stage:\n");
        fprintf(fp_out, "- Input: input.txt, sk\n");
        fprintf(fp_out, "- Output:\n");
        fprintBstr(fp_out, "* Signature: ", sm, CRYPTO_BYTES);
        fprintf(fp_out, "* Time: %.6f seconds\n", sign_time);
        fprintf(fp_out, "\n");

        // Verifying Stage
        fprintf(fp_out, "Verifying Stage:\n");
        fprintf(fp_out, "- Input: input.txt, sig, pk\n");
        fprintf(fp_out, "- Output: %s\n", valid ? "Valid" : "Invalid");
        fprintf(fp_out, "* Time: %.6f seconds\n", verify_time);
        fprintf(fp_out, "\n");

        // Total execution time
        fprintf(fp_out, "Total execution time (all 3 stages): %.6f seconds\n", total_time);
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
