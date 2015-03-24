#ifndef COMMON_ALGORITHMS_H
#define COMMON_ALGORITHMS_H
#include <gmp.h>

#include "tcb.h"
#include "mathutils.h"

typedef unsigned char * byte;

key_share_t * generate_keys(key_meta_info_t * info, public_key_t * public_key);

void clear_shares(key_share_t * shares, key_meta_info_t * info); 

void node_sign(signature_share_t * out, int node_id, const key_share_t * share, 
               const public_key_t * pk, const key_meta_info_t * info, 
               mpz_t doc);

void join_signatures(mpz_t out, mpz_t document, 
                     const signature_share_t ** signatures, int k, 
                     const public_key_t * pk, 
                     const key_meta_info_t * info);

int verify_signature(const signature_share_t * signature, mpz_t doc,
        const public_key_t * pk, const key_meta_info_t * info, 
        int id) ;

#if 1
void generate_safe_prime(mpz_t out, int bit_len, random_fn random);
key_share_t * generate_key_shares(const key_meta_info_t * info, mpz_t n, mpz_t d, mpz_t m);
void lagrange_interpolation(mpz_t out, int i, int j, int n, const signature_share_t ** signatures, mpz_t delta);
void generate_group_verifier(key_meta_info_t * info, mpz_t n);
void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares);
#endif

#endif 
