#include "tcb.h"

void init_public_key(public_key_t * pk) {
    mpz_inits(pk->n, pk->e, NULL);
}

void clear_public_key(public_key_t * pk) {
    mpz_clears(pk->n, pk->e, NULL);
}

void init_key_meta_info(key_meta_info_t * metainfo, int bit_size, int k, int l) {
    metainfo->bit_size = bit_size;
    metainfo->k = k;
    metainfo->l = l;
}

void clear_key_meta_info(key_meta_info_t * _) {
}

void init_signature_share(signature_share_t * ss) {
    mpz_inits(ss->signature, ss->c, ss->z, NULL);
}

void clear_signature_share(signature_share_t * ss) {
    mpz_clears(ss->signature, ss->c, ss->z, NULL);
}
