#ifndef TC_H
#define TC_H

#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t

typedef uint8_t byte;
struct bytes {
    byte * data;
    size_t data_len;
};
typedef struct bytes bytes_t;

typedef struct public_key public_key_t;
typedef struct key_meta_info key_meta_info_t;
typedef struct key_share key_share_t;
typedef struct signature_share signature_share_t;

enum tc_hash_type {
    TC_SHA256,
    TC_NONE
};
typedef enum tc_hash_type tc_hash_type_t;


/* Operations & Constructors */
bytes_t *tc_init_bytes(byte *bs, size_t len);
key_share_t **tc_generate_keys(key_meta_info_t **out, int bit_size, int k, int ll);
signature_share_t *tc_node_sign(const key_share_t *share, const bytes_t *doc, const key_meta_info_t *info);
bytes_t *tc_join_signatures(const signature_share_t **signatures, const bytes_t *document, const key_meta_info_t *info);
int tc_verify_signature(const signature_share_t *signature, const bytes_t *doc, const key_meta_info_t *info);
int tc_rsa_verify(bytes_t *signature, bytes_t *doc, key_meta_info_t *info, tc_hash_type_t hashtype);
bytes_t *tc_prepare_document(const bytes_t *doc, tc_hash_type_t hash_type, const key_meta_info_t *metainfo);

/* Getters */
int tc_key_meta_info_k(const key_meta_info_t *i);
int tc_key_meta_info_l(const key_meta_info_t *i);
const public_key_t *tc_key_meta_info_public_key(const key_meta_info_t *i);
int tc_key_share_id(const key_share_t *k);
const bytes_t *tc_public_key_n(const public_key_t *pk);
const bytes_t *tc_public_key_e(const public_key_t *pk);
int tc_signature_share_id(const signature_share_t *s);


/* Serializers */
char *tc_bytes_b64(const bytes_t *b);
bytes_t *tc_b64_bytes(const char *b);

/* Destructors */
void tc_clear_bytes(bytes_t *bytes);
void tc_clear_bytes_n(bytes_t *bytes, ...);
void tc_clear_key_meta_info(key_meta_info_t *info);
void tc_clear_signature_share(signature_share_t *ss);
void tc_clear_key_share(key_share_t *share);
void tc_clear_key_shares(key_share_t **shares, key_meta_info_t *info);

#endif
