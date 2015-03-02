#ifndef COMMON_ALGORITHMS_H
#define COMMON_ALGORITHMS_H
#include <gmp.h>

#include "tcb.h"
#include "mathutils.h"

typedef unsigned char * byte;

key_share_t * generate_keys(const key_meta_info_t * info, public_key_t * public_key);
void clear_shares(key_share_t * shares, key_meta_info_t * info); 

void random_prime(mpz_t rop, int bit_len, random_fn random);
void generate_strong_prime(mpz_t out, int bit_len, random_fn random);

void node_sign(signature_share_t * out, int node_id, const key_share_t * share, const public_key_t * pk, const byte * document, int document_len);
#endif 
