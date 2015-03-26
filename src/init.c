#include "tcb.h"
#include <stdlib.h>

void init_public_key(public_key_t * pk) {
    mpz_inits(pk->n, pk->e, pk->m, NULL);
}

void clear_public_key(public_key_t * pk) {
    mpz_clears(pk->n, pk->e, pk->m, NULL);
}

void init_key_meta_info(key_meta_info_t * metainfo, int bit_size, int k, int l) {
    metainfo->bit_size = bit_size;
    metainfo->k = k;
    metainfo->l = l;
}

void clear_key_meta_info(key_meta_info_t * info) {
    mpz_clears(info->vk_v, info->vk_u, NULL);
    for (int i=0; i<info->l; i++) {
        mpz_clear(info->vk_i[i]);
    }
    free(info->vk_i);
}

void init_key_shares(key_share_t * shares, key_meta_info_t * info) {
    for(int i=0; i<info->l; i++) {
        mpz_inits(shares[i].s_i, shares[i].n, NULL);
    }
}

void clear_key_shares(key_share_t * shares, key_meta_info_t * info){
    int i;
    for(i=0; i<info->l; i++) {
        mpz_clears(shares[i].s_i, shares[i].n, NULL);
    }
}

void init_signature_share(signature_share_t * ss) {
    mpz_inits(ss->signature, ss->c, ss->z, NULL);
}

void clear_signature_share(signature_share_t * ss) {
    mpz_clears(ss->signature, ss->c, ss->z, NULL);
}

