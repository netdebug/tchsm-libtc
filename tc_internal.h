#ifndef TC_INTERNAL_H
# define TC_INTERNAL_H

#include <stddef.h>

#include "tc.h"

struct public_key {
    bytes_t * n;
    bytes_t * m;
    bytes_t * e;
};

struct key_meta_info {
    public_key_t * public_key;
    int bit_size;
    int k;
    int l;
    bytes_t * vk_v;
    bytes_t * vk_i;
};

struct key_share {
    bytes_t * s_i;
    bytes_t * n;
    int id;
};

struct signature_share {
    bytes_t * signature;
    bytes_t * c;
    bytes_t * z;
    int id;
};


#define TC_OCTET_SIZE(z) ((mpz_sizeinbase(z, 2) + 7) / 8)
#define TC_GET_OCTETS(z, bcount, op) mpz_import(z, bcount, 1, 1, 0, 0, op)
#define TC_TO_OCTETS(count, op) mpz_export(NULL, count, 1, 1, 0, 0, op)
#define TC_ID_TO_INDEX(id) (id-1)
#define TC_INDEX_TO_ID(idx) (idx+1)

#define TC_MPZ_TO_BYTES(bytes, z) \
    do { bytes_t * b = (bytes); b->data = TC_TO_OCTETS(&b->data_len, z); } while(0)
#define TC_BYTES_TO_MPZ(z, bytes) \
    do { const bytes_t * __b = (bytes); mpz_import(z, __b->data_len, 1, 1, 0, 0, __b->data); } while(0)

void *alloc(size_t size);
bytes_t *tc_init_bytes(byte *bs, size_t len);
public_key_t *tc_init_public_key();
key_meta_info_t *tc_init_key_meta_info(int bit_size, int k, int l) ;
signature_share_t *tc_init_signature_share();
key_share_t *tc_init_key_share();
key_share_t **tc_init_key_shares(key_meta_info_t *info);

#endif
