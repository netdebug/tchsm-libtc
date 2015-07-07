#ifndef TC_H
#define TC_H
#include <gmp.h>

#define TC_OCTET_SIZE(z) ((mpz_sizeinbase(z, 2) + 7) / 8)
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
    public_key_t * public_key;
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

typedef unsigned char byte;

key_meta_info_t * tc_init_key_meta_info(key_meta_info_t * metainfo, int bit_size, int k, int l);
void tc_clear_key_meta_info(key_meta_info_t *);
signature_share_t * tc_init_signature_share(signature_share_t * ss);
void tc_clear_signature_share(signature_share_t * ss);

key_share_t * tc_init_key_share(key_share_t * share);
key_share_t * tc_init_key_shares(key_share_t * shares, key_meta_info_t * info); 
void tc_clear_key_shares(key_share_t * shares, key_meta_info_t * info); 
void tc_clear_key_share(key_share_t * share);

typedef enum { TC_OK=0 } tc_error_t;

tc_error_t tc_generate_keys(key_share_t * out, key_meta_info_t * info);
tc_error_t tc_node_sign(signature_share_t * out, const key_share_t * share, mpz_t doc, const key_meta_info_t * info);
tc_error_t tc_join_signatures(mpz_t out, const signature_share_t * const * signatures, mpz_t document, const key_meta_info_t * info);
int tc_verify_signature(const signature_share_t * signature, mpz_t doc, const key_meta_info_t * info);
void tc_pkcs1_encoding(byte * out, const unsigned char * digest, const char * hash_type, int modulus_size);

#endif
