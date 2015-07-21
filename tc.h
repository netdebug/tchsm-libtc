#ifndef TC_H
#define TC_H

#include <stddef.h> // for size_t

typedef unsigned char byte;

typedef struct bytes {
    byte * data;
    size_t data_len;
} bytes_t;

typedef struct public_key {
    bytes_t n;
    bytes_t m;
    bytes_t e;
} public_key_t;

typedef struct key_meta_info {
    public_key_t * public_key;
    int bit_size;
    int k;
    int l;
    bytes_t vk_v;
    bytes_t * vk_i;
} key_meta_info_t;

typedef struct key_share {
    bytes_t s_i;
    bytes_t n;
    int id;
} key_share_t; 

typedef struct signature_share {
    bytes_t signature;
    bytes_t c;
    bytes_t z;
    int id;
} signature_share_t;

void tc_clear_bytes(bytes_t * bytes);
void tc_clear_bytes_n(bytes_t * bytes, ...);

key_meta_info_t * tc_init_key_meta_info(key_meta_info_t * metainfo, int bit_size, int k, int l);
void tc_clear_key_meta_info(key_meta_info_t *);
signature_share_t * tc_init_signature_share(signature_share_t * ss);
void tc_clear_signature_share(signature_share_t * ss);

key_share_t * tc_init_key_share(key_share_t * share);
key_share_t * tc_init_key_shares(key_share_t * shares, key_meta_info_t * info); 
void tc_clear_key_shares(key_share_t * shares, key_meta_info_t * info); 
void tc_clear_key_share(key_share_t * share);

typedef enum { TC_OK=0 } tc_error_t;

typedef enum {
    TC_SHA256,
    TC_NONE
} tc_hash_type_t;

tc_error_t tc_generate_keys(key_share_t * out, key_meta_info_t * info);
tc_error_t tc_node_sign(signature_share_t * out, const key_share_t * share, const bytes_t * doc, const key_meta_info_t * info);
tc_error_t tc_join_signatures(bytes_t * out, const signature_share_t * const * signatures, const bytes_t * document, const key_meta_info_t * info);
int tc_verify_signature(const signature_share_t * signature, const bytes_t * doc, const key_meta_info_t * info);

void tc_prepare_document(bytes_t * out, const bytes_t * doc, tc_hash_type_t hash_id, const key_meta_info_t * metainfo);


#endif
