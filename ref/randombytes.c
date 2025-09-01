/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#include <fcntl.h>
#include <unistd.h>

#include "randombytes.h"

static int fd = -1;

void randombytes(unsigned char *x, unsigned long long xlen)
{
    unsigned long long i;

    if (fd == -1) {
        for (;;) {
            fd = open("/dev/urandom", O_RDONLY);
            if (fd != -1) {
                break;
            }
            sleep(1);
        }
    }

    while (xlen > 0) {
        size_t to_read;
        if (xlen < 1048576) {
            to_read = (size_t)xlen;
        }
        else {
            to_read = 1048576;
        }

        i = (unsigned long long)read(fd, x, (unsigned int)to_read);
        if (i < 1) {
            sleep(1);
            continue;
        }

        x += i;
        xlen -= i;
    }
}
