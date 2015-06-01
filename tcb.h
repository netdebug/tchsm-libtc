#ifndef TCB_H
#define TCB_H
#include <gmp.h>

#define TC_GET_OCTETS(z, bcount, op) mpz_import(z, bcount, 1, 1, 0, 0, op)
#define TC_TO_OCTETS(count, op) mpz_export(NULL, count, 1, 1, 0, 0, op)
#define TC_ID_TO_INDEX(id) (id-1)
#define TC_INDEX_TO_ID(idx) (idx+1)


typedef struct public_key {
    mpz_t n;
    mpz_t m;
    mpz_t e;
} public_key_t;

typedef struct key_meta_info {
    int bit_size;
    int k;
    int l;
    mpz_t vk_v;
    mpz_t * vk_i;
} key_meta_info_t;

typedef struct key_share {
    mpz_t s_i;
    mpz_t n;
    int id;
} key_share_t; 

typedef struct signature_share {
    mpz_t signature;
    mpz_t c;
    mpz_t z;
    int id;
} signature_share_t;

void init_public_key(public_key_t * pk);
void clear_public_key(public_key_t * pk);
void init_key_meta_info(key_meta_info_t * metainfo, int bit_size, int k, int l);
void clear_key_meta_info(key_meta_info_t *);
void init_signature_share(signature_share_t * ss);
void clear_signature_share(signature_share_t * ss);

void init_key_shares(key_share_t * shares, key_meta_info_t * info); 
void clear_key_shares(key_share_t * shares, key_meta_info_t * info); 

#endif
