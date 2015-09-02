#ifndef TC_H
#define TC_H

#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t

struct bytes {
    void *data;
    uint32_t data_len;
};
typedef struct bytes bytes_t;

typedef struct public_key public_key_t;
typedef struct key_metainfo key_metainfo_t;
typedef struct key_share key_share_t;
typedef struct signature_share signature_share_t;

enum tc_hash_type {
    TC_SHA256,
    TC_NONE
};
typedef enum tc_hash_type tc_hash_type_t;


/* Operations & Constructors */


/**
 * @ param bs pointer to data
 * @ param len data stored in len
 *
 * @ return a new bytes_t structure that stores bs with its len
 */
bytes_t *tc_init_bytes(void *bs, size_t len);

/**
 *
 * @ param out stores the corresponding key_metainfo to the key_share lists.
 * @ param bit_size the bit_size of the returned key_shares
 * @ param k the number of nodes needed to sign
 * @ param ll the number of nodes
 *
 * @ result a key_share array of ll items or NULL under error condition.
 */
key_share_t **tc_generate_keys(key_metainfo_t **out, size_t bit_size, uint16_t k, uint16_t ll);
signature_share_t *tc_node_sign(const key_share_t *share, const bytes_t *doc, const key_metainfo_t *info);
bytes_t *tc_join_signatures(const signature_share_t **signatures, const bytes_t *document, const key_metainfo_t *info);
int tc_verify_signature(const signature_share_t *signature, const bytes_t *doc, const key_metainfo_t *info);
int tc_rsa_verify(bytes_t *signature, bytes_t *doc, key_metainfo_t *info, tc_hash_type_t hashtype);
bytes_t *tc_prepare_document(const bytes_t *doc, tc_hash_type_t hash_type, const key_metainfo_t *metainfo);

/* Getters */
int tc_key_meta_info_k(const key_metainfo_t *i);
int tc_key_meta_info_l(const key_metainfo_t *i);
const public_key_t *tc_key_meta_info_public_key(const key_metainfo_t *i);
int tc_key_share_id(const key_share_t *k);
const bytes_t *tc_public_key_n(const public_key_t *pk);
const bytes_t *tc_public_key_e(const public_key_t *pk);
int tc_signature_share_id(const signature_share_t *s);


/* Serializers */
char *tc_bytes_b64(const bytes_t *b);
bytes_t *tc_b64_bytes(const char *b);

/**** Serialization Format
 * The colon means concatenation.
 * KeyShare:
 *  Base64(version :: id :: n_len :: n :: si_len :: si)
 * SignatureShare:
 *  Base64(version :: id :: xi_len :: xi :: c_len :: c :: z_len :: z)
 * PublicKey:
 *  Bytes(n :: e :: m) -> pk_len :: pk
 * KeyMetainfo:
 *  Base64(version :: pk_len :: pk :: k :: l :: vk_len :: vk :: v0_len :: v0 :: ... :: v(l-1)_len :: v(l-1))
 */
char *tc_serialize_key_share(const key_share_t *ks);
char *tc_serialize_signature_share(const signature_share_t *ss);
char *tc_serialize_key_metainfo(const key_metainfo_t *kmi);
key_share_t *tc_deserialize_key_share(const char *b64);
signature_share_t *tc_deserialize_signature_share(const char *b64);
key_metainfo_t *tc_deserialize_key_metainfo(const char *b64);

/* Destructors */
void tc_clear_bytes(bytes_t *bytes);
void tc_clear_bytes_n(bytes_t *bytes, ...);
void tc_clear_key_metainfo(key_metainfo_t *info);
void tc_clear_signature_share(signature_share_t *ss);
void tc_clear_key_share(key_share_t *share);
void tc_clear_key_shares(key_share_t **shares, key_metainfo_t *info);

#endif
