#ifndef TC_INTERNAL_H
# define TC_INTERNAL_H

#include <stddef.h>

#include "tc.h"

struct public_key {
    bytes_t * n;
    bytes_t * m;
    bytes_t * e;
};

struct key_metainfo {
    public_key_t * public_key;
    uint16_t k;
    uint16_t l;
    bytes_t * vk_v;
    bytes_t * vk_i;
};

struct key_share {
    bytes_t * s_i;
    bytes_t * n;
    uint16_t id;
};

struct signature_share {
    bytes_t *x_i;
    bytes_t *c;
    bytes_t *z;
    uint16_t id;
};


#define TC_GET_OCTETS(z, bcount, op) mpz_import(z, bcount, 1, 1, 0, 0, op)
#define TC_TO_OCTETS(count, op) mpz_export(NULL, count, 1, 1, 0, 0, op)
#define TC_ID_TO_INDEX(id) (id-1)

#define TC_MPZ_TO_BYTES(bytes, z) \
    do { bytes_t * b = (bytes); b->data = TC_TO_OCTETS(&b->data_len, z); } while(0)
#define TC_BYTES_TO_MPZ(z, bytes) \
    do { const bytes_t * __b = (bytes); mpz_import(z, __b->data_len, 1, 1, 0, 0, __b->data); } while(0)

void *alloc(size_t size);
public_key_t *tc_init_public_key();
key_metainfo_t *tc_init_key_meta_info(size_t bit_size, uint16_t k, uint16_t l) ;
signature_share_t *tc_init_signature_share();
key_share_t *tc_init_key_share();
key_share_t **tc_init_key_shares(key_metainfo_t *info);

#endif
