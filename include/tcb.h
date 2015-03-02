#ifndef TCB_H
#define TCB_H
#include <gmp.h>

typedef struct public_key {
    mpz_t n;
    mpz_t e;
} public_key_t;

typedef struct key_meta_info {
    int bit_size;
    int k;
    int l;
} key_meta_info_t;

typedef struct key_share {
    mpz_t s_i;
    mpz_t vk_i;
    mpz_t vk_v;
    mpz_t vk_u;
    mpz_t n;
} key_share_t; 

typedef struct signature_share {
    mpz_t signature;
    mpz_t c;
    mpz_t z;
} signature_share_t;

void init_public_key(public_key_t * pk);
void clear_public_key(public_key_t * pk);
void init_key_meta_info(key_meta_info_t * metainfo, int bit_size, int k, int l);
void clear_key_meta_info(key_meta_info_t *);
void init_signature_share(signature_share_t * ss);
void clear_signature_share(signature_share_t * ss);

#endif