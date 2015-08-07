#include "tc.h"
#include <stdlib.h>
#include <stdarg.h>

bytes_t * tc_init_bytes(byte * bs, size_t len) {
    bytes_t * out = malloc(sizeof(bytes_t));
    out->data = bs;
    out->data_len = len;

    return out;
}

static bytes_t * tc_init_bytes_array(size_t len) {
    bytes_t * bytes_array =  malloc(len*sizeof(bytes_t));
    return bytes_array;
}

void tc_clear_bytes(bytes_t * bytes) {
    free(bytes->data);
    free(bytes);
}

static void tc_clear_bytes_array(bytes_t * b, int count) {
    for(int i=0; i<count; i++) {
        free(b[i].data);
    }
    free(b);
}

void tc_clear_bytes_n(bytes_t * bytes, ...) {
    va_list ap;
    va_start(ap, bytes);
    
    tc_clear_bytes(bytes);

    bytes_t * cur_arg;
    while((cur_arg = va_arg(ap, bytes_t *)) != NULL) {
       tc_clear_bytes(cur_arg);
    }

    va_end(ap);
}

public_key_t * tc_init_public_key() {
    public_key_t * pk = malloc(sizeof(public_key_t));

    pk->n = tc_init_bytes(NULL, 0);
    pk->m = tc_init_bytes(NULL, 0);
    pk->e = tc_init_bytes(NULL, 0);

    return pk;
}

void tc_clear_public_key(public_key_t * pk) {
    tc_clear_bytes_n(pk->e, pk->m, pk->n, NULL);
    free(pk);
}

key_meta_info_t * tc_init_key_meta_info(int bit_size, int k, int l) {
#ifdef __CPROVER__
    __CPROVER_assert(512 <= bit_size &*& bit_size <= 8192, "Bit size limits");
    __CPROVER_assert(0 < l, "l is positive");
    __CPROVER_assert(l/2 < k && k <= l, "k is between l/2 and l");
#endif
    key_meta_info_t * metainfo = malloc(sizeof(key_meta_info_t));
    metainfo->bit_size = bit_size;
    metainfo->k = k;
    metainfo->l = l;

    metainfo->public_key = tc_init_public_key();
    metainfo->vk_i = tc_init_bytes_array(l);
    metainfo->vk_v = tc_init_bytes(NULL, 0);
    return metainfo;
}

void tc_clear_key_meta_info(key_meta_info_t * info) {
    tc_clear_public_key(info->public_key);
    tc_clear_bytes(info->vk_v);
    tc_clear_bytes_array(info->vk_i, info->l);
    free(info);
}

key_share_t * tc_init_key_share() {
    key_share_t * ks = malloc(sizeof(key_share_t));

    ks->n = tc_init_bytes(NULL, 0);
    ks->s_i = tc_init_bytes(NULL, 0);

    return ks;
}

key_share_t ** tc_init_key_shares(key_meta_info_t * info) {
#ifdef __CPROVER__
    __CPROVER_assume(info->l <= 100);
#endif
    key_share_t ** ks = malloc(sizeof(key_share_t*)*info->l);
    for(int i=0; i<info->l; i++) {
        ks[i] = tc_init_key_share();
    }

    return ks;
}

void tc_clear_key_share(key_share_t * share) { 
    tc_clear_bytes_n(share->s_i, share->n, NULL);
    free(share);
}

void tc_clear_key_shares(key_share_t ** shares, key_meta_info_t * info){
#ifdef __CPROVER__
    __CPROVER_assume(info->l <= 100);
#endif
    for(int i=0; i<info->l; i++) {
        tc_clear_key_share(shares[i]);
    }
    free(shares);
}

signature_share_t * tc_init_signature_share() {
    signature_share_t * ss = malloc(sizeof(signature_share_t));

    ss->z = tc_init_bytes(NULL, 0);
    ss->c = tc_init_bytes(NULL, 0);
    ss->signature = tc_init_bytes(NULL, 0);

    return ss;
}

void tc_clear_signature_share(signature_share_t * ss) {
    tc_clear_bytes_n(ss->signature, ss->c, ss->z, NULL);
    free(ss);
}
