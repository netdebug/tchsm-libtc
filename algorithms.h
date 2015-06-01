#ifndef COMMON_ALGORITHMS_H
#define COMMON_ALGORITHMS_H
#include <gmp.h>

#include "tcb.h"
#include "mathutils.h"

#define OCTET_SIZE(z) ((mpz_sizeinbase(z, 2) + 7) / 8)

typedef unsigned char byte;
typedef enum { TC_OK=0 } tc_error_t;
static const unsigned int HASH_LEN = 32; // sha256 => 256 bits => 32 bytes

tc_error_t generate_keys(key_share_t * out, public_key_t * pk, key_meta_info_t * info);

tc_error_t node_sign(signature_share_t * out, const key_share_t * share, mpz_t doc, 
        const public_key_t * pk, const key_meta_info_t * info);

tc_error_t join_signatures(mpz_t out, const signature_share_t * signatures, int k, mpz_t document,
        const public_key_t * pk, const key_meta_info_t * info);

int verify_signature(const signature_share_t * signature, mpz_t doc,
        const public_key_t * pk, const key_meta_info_t * info) ;

void pkcs1_encoding(byte * out, const unsigned char * digest, const char * hash_type, int modulus_size);

#endif
