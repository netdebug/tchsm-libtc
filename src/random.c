#include <stdlib.h>
#include <stdio.h>

#include "mathutils.h"

void random_dev(mpz_t rop, int bit_len) {
    int byte_size = (bit_len + 7) / 8;
    void * buffer = malloc(byte_size);
    
    FILE * dev = fopen("/dev/urandom", "r");
    int read = fread(buffer, 1, byte_size, dev);
    while(read < byte_size) {
        read += fread(buffer + read, 1, byte_size - read, dev);
    }
    fclose(dev);
     
    mpz_import(rop, byte_size, 1, 1, 1, 0, buffer);
    free(buffer);
    
}

void random_prime(mpz_t rop, int bit_len, random_fn random) {
    mpz_t r;
    mpz_init(r);
    
    int size;
    do {
        random(r, bit_len);
        mpz_nextprime(rop, r);
    
        size = mpz_sizeinbase(rop, 2);
    } while (size > bit_len);
    
    mpz_clear(r);
} 
