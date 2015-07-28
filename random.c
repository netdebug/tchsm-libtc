#include "mathutils.h"

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <gmp.h>

void random_dev(mpz_t rop, int bit_len) {
  assert(bit_len > 0);
  int byte_size = bit_len / 8;
  void * buffer = malloc(byte_size);

  FILE * dev = fopen("/dev/urandom", "r");
  int read = fread(buffer, 1, byte_size, dev);
  while(read < byte_size) {
    read += fread(buffer + read, 1, byte_size - read, dev);
  }
  fclose(dev);

  mpz_import(rop, byte_size, 1, 1, 0, 0, buffer);
  free(buffer);

  assert(mpz_sizeinbase(rop, 2) <= bit_len);
}

void random_prime(mpz_t rop, int bit_len, random_fn random) {
  assert(bit_len > 0 && random != NULL);
  mpz_t r;
  mpz_init(r);

  int size;
  do {
    random(r, bit_len);
    mpz_nextprime(rop, r);
    size = mpz_sizeinbase(rop, 2);
  } while (size > bit_len);

  mpz_clear(r);
  assert(mpz_sizeinbase(rop, 2) <= bit_len && mpz_probab_prime_p(rop, 25));
}
