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

void init_signature_share(signature_share_t * ss) {
    mpz_inits(ss->signature, ss->c, ss->z, NULL);
}

void clear_signature_share(signature_share_t * ss) {
    mpz_clears(ss->signature, ss->c, ss->z, NULL);
}

signature_share_t ** create_signature_shares(key_meta_info_t const * info) {
    int n = info->l;
    signature_share_t ** out = malloc(n * sizeof(*out));
    for(int i=0; i<n; i++) {
        out[i] = malloc(sizeof(**out));
        init_signature_share(out[i]);
    }
    return out;
}

void destroy_signature_shares(signature_share_t ** out, key_meta_info_t const * info) {
    int n = info->l;
    for(int i=0; i<n; i++) {
        clear_signature_share(out[i]);
        free(out[i]);
    }
    free(out);
}

