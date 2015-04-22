#ifndef COMMON_ALGORITHMS_H
#define COMMON_ALGORITHMS_H
#include <gmp.h>

#include "tcb.h"
#include "mathutils.h"

typedef unsigned char byte;
typedef enum { TC_OK=0 } tc_error_t;
static const unsigned int HASH_LEN = 32; // sha256 => 256 bits => 32 bytes

tc_error_t generate_keys(key_share_t * out, public_key_t * pk, key_meta_info_t * info);

tc_error_t node_sign(signature_share_t * out, const key_share_t * share, int node_id, mpz_t doc, 
        const public_key_t * pk, const key_meta_info_t * info);

tc_error_t join_signatures(mpz_t out, const signature_share_t * signatures, int k, mpz_t document,
        const public_key_t * pk, const key_meta_info_t * info);

tc_error_t verify_signature(const signature_share_t * signature, int id, mpz_t doc,
        const public_key_t * pk, const key_meta_info_t * info) ;

byte * pkcs1_encoding(mpz_t signature, char * hash, public_key_t const * pk);

#endif
