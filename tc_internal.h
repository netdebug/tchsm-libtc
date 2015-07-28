#ifndef TC_INTERNAL_H
# define TC_INTERNAL_H

#include <gmp.h>
#include "tc.h"

#define TC_OCTET_SIZE(z) ((mpz_sizeinbase(z, 2) + 7) / 8)
#define TC_GET_OCTETS(z, bcount, op) mpz_import(z, bcount, 1, 1, 0, 0, op)
#define TC_TO_OCTETS(count, op) mpz_export(NULL, count, 1, 1, 0, 0, op)
#define TC_ID_TO_INDEX(id) (id-1)
#define TC_INDEX_TO_ID(idx) (idx+1)

#define TC_MPZ_TO_BYTES(bytes, z) \
    do { bytes_t * b = (bytes); b->data = TC_TO_OCTETS(&b->data_len, z); } while(0)
#define TC_BYTES_TO_MPZ(z, bytes) \
    do { const bytes_t * b = (bytes); TC_GET_OCTETS(z, b->data_len, b->data); } while(0)

bytes_t * tc_init_bytes(byte * bs, size_t len);
public_key_t * tc_init_public_key();
key_meta_info_t * tc_init_key_meta_info(int bit_size, int k, int l) ;
signature_share_t * tc_init_signature_share();
key_share_t * tc_init_key_share();
key_share_t ** tc_init_key_shares(key_meta_info_t * info);

#endif
