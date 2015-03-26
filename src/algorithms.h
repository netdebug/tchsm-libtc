#ifndef COMMON_ALGORITHMS_H
#define COMMON_ALGORITHMS_H
#include <gmp.h>

#include "tcb.h"
#include "mathutils.h"

typedef unsigned char * byte;
static const unsigned int HASH_LEN = 32; // sha256 => 256 bits => 32 bytes

void generate_keys(key_share_t * out, key_meta_info_t * info, public_key_t * public_key);


void node_sign(signature_share_t * out, const key_share_t * share, int node_id, 
        mpz_t doc, const public_key_t * pk, const key_meta_info_t * info);

void join_signatures(mpz_t out, 
        const signature_share_t * signatures, int k, 
        mpz_t document, 
        const public_key_t * pk,
        const key_meta_info_t * info);

int verify_signature(const signature_share_t * signature, int id, mpz_t doc,
        const public_key_t * pk, const key_meta_info_t * info) ;

/* UTILS: TODO: move this after tests */
void generate_safe_prime(mpz_t out, int bit_len, random_fn random);
void generate_key_shares(key_share_t * shares, const key_meta_info_t * info, mpz_t n, mpz_t d, mpz_t m);
void lagrange_interpolation(mpz_t out, int i, int j, int n, const signature_share_t * signatures, mpz_t delta);
void generate_group_verifier(key_meta_info_t * info, mpz_t n);
void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares);

#endif 
