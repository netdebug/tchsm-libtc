#include "tc.h"
#include <stdlib.h>
#include <stdarg.h>

static inline void clear_bytes(bytes_t * bytes) {
    free(bytes->data);
}

static inline void clear_bytes_n(bytes_t * bytes, ...) {
    va_list ap;
    va_start(ap, bytes);
    
    clear_bytes(bytes);

    bytes_t * cur_arg;
    while((cur_arg = va_arg(ap, bytes_t *)) != NULL) {
       clear_bytes(cur_arg);
    }

    va_end(ap);
}

public_key_t * tc_init_public_key(public_key_t * pk) {
    return pk;
}

void tc_clear_public_key(public_key_t * pk) {
    clear_bytes_n(&pk->e, &pk->m, &pk->n, NULL);
}

key_meta_info_t * tc_init_key_meta_info(key_meta_info_t * metainfo, int bit_size, int k, int l) {
    metainfo->bit_size = bit_size;
    metainfo->k = k;
    metainfo->l = l;

    metainfo->public_key = tc_init_public_key(malloc(sizeof(public_key_t)));
    metainfo->vk_i = malloc(l * sizeof(bytes_t));
    return metainfo;
}

void tc_clear_key_meta_info(key_meta_info_t * info) {
    tc_clear_public_key(info->public_key);
    free(info->public_key);

    clear_bytes(&info->vk_v);
    for (int i=0; i<info->l; i++) {
        clear_bytes(&info->vk_i[i]);
    }
    free(info->vk_i);
}

key_share_t * tc_init_key_share(key_share_t * share) {
    return share;
}

key_share_t * tc_init_key_shares(key_share_t * shares, key_meta_info_t * info) {
    return shares;
}

void tc_clear_key_share(key_share_t * share) { 
    clear_bytes_n(&share->s_i, &share->n, NULL);
}

void tc_clear_key_shares(key_share_t * shares, key_meta_info_t * info){
    int i;
    for(i=0; i<info->l; i++) {
        tc_clear_key_share(shares + i);
    }
}

signature_share_t * tc_init_signature_share(signature_share_t * ss) {
    return ss;
}

void tc_clear_signature_share(signature_share_t * ss) {
    clear_bytes_n(&ss->signature, &ss->c, &ss->z, NULL);
}

