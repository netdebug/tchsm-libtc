#include "tc.h"
#include <stdlib.h>

void tc_init_public_key(public_key_t * pk) {
    mpz_inits(pk->n, pk->e, pk->m, NULL);
}

void tc_clear_public_key(public_key_t * pk) {
    mpz_clears(pk->n, pk->e, pk->m, NULL);
}

void tc_init_key_meta_info(key_meta_info_t * metainfo, int bit_size, int k, int l) {
    metainfo->bit_size = bit_size;
    metainfo->k = k;
    metainfo->l = l;
}

void tc_clear_key_meta_info(key_meta_info_t * info) {
    mpz_clears(info->vk_v, NULL);
    for (int i=0; i<info->l; i++) {
        mpz_clear(info->vk_i[i]);
    }
    free(info->vk_i);
}

void tc_init_key_share(key_share_t * share) {
    mpz_inits(share->s_i, share->n, NULL);
}

void tc_init_key_shares(key_share_t * shares, key_meta_info_t * info) {
    for(int i=0; i<info->l; i++) {
        tc_init_key_share(shares+i);
    }
}

void tc_clear_key_share(key_share_t * share) { 
    mpz_clears(share->s_i, share->n, NULL);
}

void tc_clear_key_shares(key_share_t * shares, key_meta_info_t * info){
    int i;
    for(i=0; i<info->l; i++) {
        tc_clear_key_share(shares + i);
    }
}

void tc_init_signature_share(signature_share_t * ss) {
    mpz_inits(ss->signature, ss->c, ss->z, NULL);
}

void tc_clear_signature_share(signature_share_t * ss) {
    mpz_clears(ss->signature, ss->c, ss->z, NULL);
}

