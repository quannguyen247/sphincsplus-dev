#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../api.h"
#include "../params.h"
#include "../randombytes.h"

#define SPX_MLEN 32
#define SPX_SIGNATURES 1

int main(void)
{
    int ret = 0;
    int i;

    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    printf("==================== STARTING SPHINCS+ TEST (spx.c) ====================\n");

    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char *m = malloc(SPX_MLEN);
    unsigned char *sm = malloc(SPX_BYTES + SPX_MLEN);
    unsigned char *mout = malloc(SPX_BYTES + SPX_MLEN);
    unsigned long long smlen;
    unsigned long long mlen;

    randombytes(m, SPX_MLEN);

    printf("\n[PHASE 1: KEY GENERATION]\n");
    printf("Generating keypair... ");

    if (crypto_sign_keypair(pk, sk)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    printf("  - Public Key Size: %d bytes\n", SPX_PK_BYTES);
    printf("  - Secret Key Size: %d bytes\n", SPX_SK_BYTES);
    printf("[PHASE 1: KEY GENERATION] - COMPLETE\n");

    printf("\n[PHASE 2 & 3: SIGNING & VERIFICATION]\n");
    printf("Testing %d signature(s)...\n", SPX_SIGNATURES);

    for (i = 0; i < SPX_SIGNATURES; i++) {
        printf("\n--- Iteration #%d ---\n", i);

        printf("  [SUB-PHASE: SIGNING]\n");
        printf("    Signing a %d-byte message... ", SPX_MLEN);
        crypto_sign(sm, &smlen, m, SPX_MLEN, sk);
        printf("done.\n");

        if (smlen != SPX_BYTES + SPX_MLEN) {
            printf("    X smlen incorrect [%llu != %u]!\n",
                   smlen, SPX_BYTES);
            ret = -1;
        }
        else {
            printf("    - Signed message length: %llu bytes (as expected).\n", smlen);
        }

        printf("\n  [SUB-PHASE: VERIFICATION]\n");
        /* Test if signature is valid. */
        printf("    Test 1: Verifying the signature... ");
        if (crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
            printf("failed!\n");
            ret = -1;
        }
        else {
            printf("succeeded.\n");
        }

        /* Test if the correct message was recovered. */
        if (mlen != SPX_MLEN) {
            printf("    X mlen incorrect [%llu != %u]!\n", mlen, SPX_MLEN);
            ret = -1;
        }
        else {
            printf("    - Recovered message length: %llu bytes (as expected).\n", mlen);
        }
        if (memcmp(m, mout, SPX_MLEN)) {
            printf("    X output message incorrect!\n");
            ret = -1;
        }
        else {
            printf("    - Recovered message content matches original (as expected).\n");
        }

        /* Test if signature is valid when validating in-place. */
        printf("    Test 2: Verifying the signature in-place... ");
        if (crypto_sign_open(sm, &mlen, sm, smlen, pk)) {
            printf("failed!\n");
            ret = -1;
        }
        else {
            printf("succeeded.\n");
        }

        /* Test if flipping bits invalidates the signature (it should). */
        printf("    Test 3: Tampering with message bit... ");
        /* Flip the first bit of the message. Should invalidate. */
        sm[smlen - 1] ^= 1;
        if (!crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
            printf("signature correctly invalidated.\n");
        }
        else {
            printf("ERROR! Signature still valid!\n");
            ret = -1;
        }
        sm[smlen - 1] ^= 1;

#ifdef SPX_TEST_INVALIDSIG
        int j;
        printf("    Test 4: Tampering with signature bits...\n");
        /* Flip one bit per hash; the signature is entirely hashes. */
        for (j = 0; j < (int)(smlen - SPX_MLEN); j += SPX_N) {
            sm[j] ^= 1;
            if (!crypto_sign_open(mout, &mlen, sm, smlen, pk)) {
                /* This is the expected outcome. */
            }
            else {
                printf("      X flipping bit %d DID NOT invalidate signature!\n", j);
                sm[j] ^= 1;
                ret = -1;
                break;
            }
            sm[j] ^= 1;
        }
        if (j >= (int)(smlen - SPX_MLEN)) {
            printf("      - Changing any signature hash correctly invalidates signature.\n");
        }
#endif
    }

    printf("\n==================== SPHINCS+ TEST (spx.c) COMPLETE ====================\n");

    free(m);
    free(sm);
    free(mout);

    return ret;
}
