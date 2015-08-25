#include <assert.h>
#include <mhash.h>
#include <stdlib.h>
#include <string.h>

#include "tc_internal.h"

const uint8_t MD2_PKCS_ID[] = {
    0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10 };

const uint8_t MD5_PKCS_ID[] = {
    0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };

const uint8_t RIPEMD_128_PKCS_ID[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02,
    0x02, 0x05, 0x00, 0x04, 0x14 };

const uint8_t RIPEMD_160_PKCS_ID[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02,
    0x01, 0x05, 0x00, 0x04, 0x14 };

const uint8_t SHA_160_PKCS_ID[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02,
    0x1A, 0x05, 0x00, 0x04, 0x14 };

const uint8_t SHA_224_PKCS_ID[] = {
    0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C };

const uint8_t SHA_256_PKCS_ID[] = {
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

const uint8_t SHA_384_PKCS_ID[] = {
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };

const uint8_t SHA_512_PKCS_ID[] = {
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

const uint8_t TIGER_PKCS_ID[] = {
    0x30, 0x29, 0x30, 0x0D, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04,
    0x01, 0xDA, 0x47, 0x0C, 0x02, 0x05, 0x00, 0x04, 0x18 };

static inline void get_hash_properties(const uint8_t ** id, int * id_len, int * digest_len, tc_hash_type_t hash_type) {
    switch(hash_type) {
        case TC_SHA256:
            *id_len = sizeof(SHA_256_PKCS_ID);
            *digest_len = 256/8;
            *id = SHA_256_PKCS_ID;
            break;
        case TC_NONE:
            *id_len = 0;
            *digest_len = 0;
            *id = NULL;
            break;
        default:
            abort();
    }
}

static void tc_pkcs1_encoding(bytes_t * out, bytes_t * digest, tc_hash_type_t hash_type) {
    int k = out->data_len;
    const uint8_t *hash_desc;
    int hash_desc_len, digest_len;

    get_hash_properties(&hash_desc, &hash_desc_len, &digest_len, hash_type);

    assert(digest->data_len <= digest_len);

    int D_len = digest_len + hash_desc_len;
    int P_len = k - 3 - D_len;

    uint8_t *p = out->data;

    /* PKCS1 padding */
    *p++ = 0x00;
    *p++ = 0x01;
    memset(p, 0xFF, P_len);
    p += P_len;
    *p++ = 0x00;

    if (hash_desc != NULL) { // ASN.1
        memcpy(p, hash_desc, hash_desc_len);
    }

    p += hash_desc_len;

    memcpy(p, digest->data, digest->data_len);
}

bytes_t * tc_prepare_document(const bytes_t * doc, tc_hash_type_t hash_type, const key_meta_info_t * metainfo) {
    size_t data_len = metainfo->public_key->n->data_len;

    bytes_t * out = tc_init_bytes(malloc(data_len), data_len);
    bytes_t digest;
    switch(hash_type) {
        case TC_SHA256:
            {
                uint8_t hash[32];
                MHASH sha = mhash_init(MHASH_SHA256);
                mhash(sha, doc->data, doc->data_len);
                mhash_deinit(sha, hash);

                digest.data = hash;
                digest.data_len = 32;
            }
            break;
        case TC_NONE:
            {
                digest.data = doc->data;
                digest.data_len = doc->data_len;
            }
            break;
        default:
            abort();
    };

    assert(digest.data_len <= data_len);
    tc_pkcs1_encoding(out, &digest, hash_type);
    return out;
}
