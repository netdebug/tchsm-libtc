#include <string.h>
#include <stdlib.h>
#include "tc_internal.h"

static const uint16_t version = 1;

#define SERIALIZE_VARIABLE(dst, x) \
    do { memcpy(dst, &x, sizeof x); dst += sizeof x; } while(0)
#define SERIALIZE_BYTES(dst, bs) \
    do { \
        bytes_t * b = (bs); \
        uint32_t net_len = htonl(b->data_len); \
        SERIALIZE_VARIABLE(dst, net_len); \
        memcpy(dst, b->data, b->data_len); \
        dst += b->data_len; \
    } while(0)

char *tc_serialize_key_share(const key_share_t *ks) {
    /*
     * We are going to write each struct component directly in memory, and then write that as a base64 string.
     */

    /* First we get the size of each component */
    uint16_t net_version = htons(version);
    uint16_t net_id = htons(ks->id);

    /* We prepare the buffer */
    size_t buffer_size = sizeof(net_version) + sizeof(net_id) + sizeof(ks->n->data_len) +
                         sizeof(ks->s_i->data_len) + ks->n->data_len + ks->s_i->data_len;
    void *buffer = malloc(buffer_size);

    /* Copy each field to the buffer */
    void *p = buffer;

    SERIALIZE_VARIABLE(p, net_version);
    SERIALIZE_VARIABLE(p, net_id);
    SERIALIZE_BYTES(p, ks->n);
    SERIALIZE_BYTES(p, ks->s_i);

    bytes_t bs = {buffer, (uint32_t) buffer_size};
    char *b64 = tc_bytes_b64(&bs);

    free(buffer);

    return b64;
}

char *tc_serialize_signature_share(const signature_share_t *ss) {
    uint16_t net_version = htons(version);
    uint16_t net_id = htons(ss->id);

    size_t buffer_size = sizeof(net_version) + sizeof(net_id) + sizeof(ss->x_i->data_len) +
                         sizeof(ss->c->data_len) + sizeof(ss->z->data_len) + ss->x_i->data_len + ss->c->data_len +
                         ss->z->data_len;
    void *buffer = malloc(buffer_size);

    void *p = buffer;
    SERIALIZE_VARIABLE(p, net_version);
    SERIALIZE_VARIABLE(p, net_id);
    SERIALIZE_BYTES(p, ss->x_i);
    SERIALIZE_BYTES(p, ss->c);
    SERIALIZE_BYTES(p, ss->z);

    bytes_t bs = {buffer, (uint32_t) buffer_size};
    char *b64 = tc_bytes_b64(&bs);
    free(buffer);
    return b64;
}

static bytes_t *serialize_public_key(const public_key_t *pk) {
    size_t buffer_size = sizeof(pk->n->data_len) + sizeof(pk->e->data_len) + sizeof(pk->m->data_len) +
                         pk->n->data_len + pk->m->data_len + pk->e->data_len;
    void *buffer = malloc(buffer_size);


    void *p = buffer;
    SERIALIZE_BYTES(p, pk->n);
    SERIALIZE_BYTES(p, pk->e);
    SERIALIZE_BYTES(p, pk->m);

    bytes_t *bs = tc_init_bytes(buffer, buffer_size);

    return bs;
}

char *tc_serialize_key_metainfo(const key_metainfo_t *kmi) {
    size_t buffer_size = 0;

    uint16_t net_version = htons(version);
    buffer_size += sizeof net_version;

    bytes_t *pk = serialize_public_key(kmi->public_key);
    buffer_size += pk->data_len;

    uint16_t net_k = htons(kmi->k);
    buffer_size += sizeof net_k;

    uint16_t net_l = htons(kmi->l);
    buffer_size += sizeof net_l;

    bytes_t *vk_v = kmi->vk_v;
    buffer_size += vk_v->data_len;

    for (int i = 0; i < kmi->l; i++) {
        buffer_size += kmi->vk_i[i].data_len;
    }

    uint8_t *buffer = malloc(buffer_size);
    void *p = buffer;

    SERIALIZE_VARIABLE(p, net_version);
    SERIALIZE_BYTES(p, pk);
    SERIALIZE_VARIABLE(p, net_k);
    SERIALIZE_VARIABLE(p, net_l);
    SERIALIZE_BYTES(p, vk_v);
    for (int i = 0; i < kmi->l; i++) {
        bytes_t *v = &kmi->vk_i[i];
        SERIALIZE_BYTES(p, v);
    }

    bytes_t bs = {buffer, buffer_size};
    char *b64 = tc_bytes_b64(&bs);
    free(buffer);

    return b64;
}

#define DESERIALIZE_SHORT(dst, buf) \
    do { memcpy(&dst, buf, sizeof dst); dst = ntohs(dst); p += sizeof dst; } while (0)

#define DESERIALIZE_BYTES(dst, buf) \
    do { uint32_t len; memcpy(&len, buf, sizeof(len)); len = ntohl(len); buf += sizeof(len);\
     bytes_t * b = (dst); b->data = alloc(len); b->data_len = len; memcpy(b->data, buf, len); \
     buf += len; } while(0)

key_share_t *tc_deserialize_key_share(const char *b64) {
    bytes_t *buffer = tc_b64_bytes(b64);
    uint8_t *p = buffer->data;

    uint16_t version;
    DESERIALIZE_SHORT(version, p);

    key_share_t *ks = tc_init_key_share();

    DESERIALIZE_SHORT(ks->id, p);
    DESERIALIZE_BYTES(ks->n, p);
    DESERIALIZE_BYTES(ks->s_i, p);

    tc_clear_bytes(buffer);

    return ks;
}

signature_share_t *tc_deserialize_signature_share(const char *b64) {
    bytes_t *buffer = tc_b64_bytes(b64);
    void *p = buffer->data;


    uint16_t version;
    DESERIALIZE_SHORT(version, p);

    signature_share_t *ss = tc_init_signature_share();
    DESERIALIZE_SHORT(ss->id, p);
    DESERIALIZE_BYTES(ss->x_i, p);
    DESERIALIZE_BYTES(ss->c, p);
    DESERIALIZE_BYTES(ss->z, p);

    tc_clear_bytes(buffer);

    return ss;
}

key_metainfo_t *tc_deserialize_key_metainfo(const char *b64) {
    bytes_t *buffer = tc_b64_bytes(b64);
    void *p = buffer->data;

    uint16_t version;
    DESERIALIZE_SHORT(version, p);

    bytes_t *pk = tc_init_bytes(NULL, 0);
    DESERIALIZE_BYTES(pk, p);

    uint16_t k;
    DESERIALIZE_SHORT(k, p);

    uint16_t l;
    DESERIALIZE_SHORT(l, p);

    key_metainfo_t *kmi = tc_init_key_metainfo(k, l);
    DESERIALIZE_BYTES(kmi->vk_v, p);
    // We have to do this here, because init_key_meta_info initializes the vk_i array.
    for (int i = 0; i < l; i++) {
        bytes_t *v = kmi->vk_i + i;
        DESERIALIZE_BYTES(kmi->vk_i + i, p);
    }
    p = pk->data;
    DESERIALIZE_BYTES(kmi->public_key->n, p);
    DESERIALIZE_BYTES(kmi->public_key->e, p);
    DESERIALIZE_BYTES(kmi->public_key->m, p);

    tc_clear_bytes(buffer);
    return kmi;
}


#ifndef NO_CHECK

#include <check.h>
#include <stdio.h>

static int bytes_eq(bytes_t *a, bytes_t *b) {
    return (a->data_len == b->data_len) &&
            (memcmp(a->data, b->data, a->data_len) == 0);
}

START_TEST(test_serialization_key_share)
    {
        key_metainfo_t *info;
        key_share_t **shares = tc_generate_keys(&info, 512, 3, 5);

        char *share0_b64 = tc_serialize_key_share(shares[0]);

        key_share_t *share0 = tc_deserialize_key_share(share0_b64);

        ck_assert(shares[0]->id == share0->id);
        ck_assert(bytes_eq(shares[0]->n, share0->n));
        ck_assert(bytes_eq(shares[0]->s_i, share0->s_i));
    }
END_TEST

START_TEST(test_serialization_signature_share)
    {
        key_metainfo_t *info;
        key_share_t **shares = tc_generate_keys(&info, 512, 3, 5);

        const char *message = "Hola mundo";
        bytes_t *doc = tc_init_bytes(strdup(message), strlen(message));
        bytes_t *doc_pkcs1 = tc_prepare_document(doc, TC_SHA256, info);

        signature_share_t *s = tc_node_sign(shares[0], doc_pkcs1, info);

        char *signature_b64 = tc_serialize_signature_share(s);
        signature_share_t *new_s = tc_deserialize_signature_share(signature_b64);

        ck_assert(s->id == new_s->id);
        ck_assert(bytes_eq(s->c, new_s->c));
        ck_assert(bytes_eq(s->x_i, new_s->x_i));
        ck_assert(bytes_eq(s->z, new_s->z));
    }
END_TEST
START_TEST(test_serialization_key_metainfo)
    {
        // TODO: Make this pass...
        key_metainfo_t *mi;
        key_share_t **shares = tc_generate_keys(&mi, 512, 4, 7);

        char *mi_b64 = tc_serialize_key_metainfo(mi);
        key_metainfo_t *new_mi = tc_deserialize_key_metainfo(mi_b64);

        ck_assert(mi->k == new_mi->k);
        ck_assert(mi->l == new_mi->l);
        ck_assert(bytes_eq(mi->public_key->n, new_mi->public_key->n));
        ck_assert(bytes_eq(mi->public_key->m, new_mi->public_key->m));
        ck_assert(bytes_eq(mi->public_key->e, new_mi->public_key->e));
        ck_assert(bytes_eq(mi->vk_v, new_mi->vk_v));
        for(int i=0; i<mi->l; i++) {
            bytes_t * a = mi->vk_i + i;
            bytes_t * b = new_mi->vk_i + i;

            for (int i = 0; i < a->data_len; i++) { printf("%02x ", ((uint8_t*)a->data)[i]); }
            printf("\n");
            for (int i = 0; i < b->data_len; i++) { printf("%02x ", ((uint8_t*)b->data)[i]); }
            printf("\ni=%d\n a == b? : %d\n", i, bytes_eq(a,b));

            ck_assert(bytes_eq(a, b));
        }
    }
END_TEST


TCase *tc_test_case_serialization() {
    TCase *tc = tcase_create("poly.c");
    tcase_add_test(tc, test_serialization_key_share);
    tcase_add_test(tc, test_serialization_signature_share);
    tcase_add_test(tc, test_serialization_key_metainfo);
    return tc;
}

#endif