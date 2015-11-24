#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tc_internal.h"

void * alloc(size_t size) {
	void * b = malloc(size);
	if (b == NULL) {
		perror("alloc");
		abort();
	}
	return b;
}

bytes_t * tc_init_bytes(void * bs, size_t len) {
    bytes_t * out = alloc(sizeof(bytes_t));
    out->data = bs;
    out->data_len = len;

    return out;
}

bytes_t *tc_init_bytes_copy(void *bs, size_t len) {
    bytes_t * out = alloc(sizeof(bytes_t));
    out->data = memcpy(malloc(len), bs, len);
    out->data_len = len;

    return out;
}

static bytes_t * tc_init_bytes_array(size_t len) {
    bytes_t * bytes_array =  alloc(len*sizeof(bytes_t));
    return bytes_array;
}

void tc_clear_bytes(bytes_t * bytes) {
    free(bytes->data);
    free(bytes);
}

void* tc_release_bytes(bytes_t *bytes, uint32_t *len) {
    if(len != NULL) {
        *len = bytes->data_len;
    }
    void *data = bytes->data;
    free(bytes);

    return data;
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
    public_key_t * pk = alloc(sizeof(public_key_t));

    pk->n = tc_init_bytes(NULL, 0);
    pk->e = tc_init_bytes(NULL, 0);

    return pk;
}


void tc_clear_public_key(public_key_t * pk) {
    tc_clear_bytes_n(pk->e, pk->n, NULL);
    free(pk);
}

key_metainfo_t *tc_init_key_metainfo(uint16_t k, uint16_t l) {
    assert(0 < l);
    assert(l/2 < k && k <= l);

    key_metainfo_t * metainfo = alloc(sizeof(key_metainfo_t));

    metainfo->k = k;
    metainfo->l = l;

    metainfo->public_key = tc_init_public_key();
    metainfo->vk_i = tc_init_bytes_array(l);
    metainfo->vk_v = tc_init_bytes(NULL, 0);
    metainfo->vk_u = tc_init_bytes(NULL, 0);

    assert(metainfo != NULL);
    return metainfo;
}

int tc_key_meta_info_k(const key_metainfo_t *i) {
    return i->k;
}

int tc_key_meta_info_l(const key_metainfo_t *i) {
    return i->l;
}

const public_key_t *tc_key_meta_info_public_key(const key_metainfo_t *i) {
    return i->public_key;
}

int tc_key_share_id(const key_share_t *k) {
    return k->id;
}

const bytes_t * tc_public_key_n(const public_key_t *pk) {
    return pk->n;
}

const bytes_t * tc_public_key_e(const public_key_t *pk) {
    return pk->e;
}

int tc_signature_share_id(const signature_share_t *s) {
    return s->id;
}

void tc_clear_key_metainfo(key_metainfo_t * info) {
	assert(info != NULL);
    tc_clear_public_key(info->public_key);
    tc_clear_bytes(info->vk_v);
    tc_clear_bytes(info->vk_u);
    tc_clear_bytes_array(info->vk_i, info->l);
    free(info);
}

key_share_t * tc_init_key_share() {
    key_share_t * ks = alloc(sizeof(key_share_t));

    ks->n = tc_init_bytes(NULL, 0);
    ks->s_i = tc_init_bytes(NULL, 0);

    return ks;
}

key_share_t ** tc_init_key_shares(key_metainfo_t * info) {
	assert(info != NULL);
	assert(info->l > 0);

    key_share_t ** ks = alloc(sizeof(key_share_t*)*info->l);
    for(int i=0; i<info->l; i++) {
        ks[i] = tc_init_key_share();
    }

    assert(ks != NULL);
    return ks;
}

void tc_clear_key_share(key_share_t * share) { 
    tc_clear_bytes_n(share->s_i, share->n, NULL);
    free(share);
}

void tc_clear_key_shares(key_share_t ** shares, key_metainfo_t * info){
	assert(info != NULL && info->l > 0);
    for(int i=0; i<info->l; i++) {
        tc_clear_key_share(shares[i]);
    }
    free(shares);
}

signature_share_t * tc_init_signature_share() {
    signature_share_t * ss = alloc(sizeof(signature_share_t));

    ss->z = tc_init_bytes(NULL, 0);
    ss->c = tc_init_bytes(NULL, 0);
    ss->x_i = tc_init_bytes(NULL, 0);

    assert(ss != NULL);
    return ss;
}

void tc_clear_signature_share(signature_share_t * ss) {
    tc_clear_bytes_n(ss->x_i, ss->c, ss->z, NULL);
    free(ss);
}
