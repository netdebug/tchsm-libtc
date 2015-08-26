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

    for (int i=0; i < kmi->l; i++) {
        buffer_size += kmi->vk_i[i].data_len;
    }

    void *buffer = malloc(buffer_size);
    void *p = buffer;

    SERIALIZE_VARIABLE(p, net_version);
    SERIALIZE_BYTES(p, pk);
    SERIALIZE_VARIABLE(p, net_k);
    SERIALIZE_VARIABLE(p, net_l);
    SERIALIZE_BYTES(p, vk_v);
    for (int i=0; i<kmi->l; i++) {
        SERIALIZE_BYTES(p, kmi->vk_i + i);
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
     bytes_t * b = (dst) = tc_init_bytes(alloc(len), len); memcpy(b->data, buf, len); \
     buf += len; } while(0)

key_share_t *tc_deserialize_key_share(const char *b64) {
    bytes_t *buffer = tc_b64_bytes(b64);
    uint8_t *p = buffer->data;

    uint16_t version;
    DESERIALIZE_SHORT(version, p);

    uint16_t id;
    DESERIALIZE_SHORT(id, p);

    bytes_t *n;
    DESERIALIZE_BYTES(n, p);

    bytes_t *s_i;
    DESERIALIZE_BYTES(s_i, p);

    key_share_t *ks = tc_init_key_share();
    ks->id = id;
    ks->n = n;
    ks->s_i = s_i;

    tc_clear_bytes(buffer);

    return ks;
}

signature_share_t *tc_deserialize_signature_share(const char *b64) {
    bytes_t *buffer = tc_b64_bytes(b64);
    void *p = buffer;


    uint16_t version;
    DESERIALIZE_SHORT(version, p);

    uint16_t id;
    DESERIALIZE_SHORT(id, p);

    bytes_t *x_i;
    DESERIALIZE_BYTES(x_i, p);

    bytes_t *c;
    DESERIALIZE_BYTES(c, p);

    bytes_t *z;
    DESERIALIZE_BYTES(z, p);

    signature_share_t *ss = tc_init_signature_share();
    ss->id = id;
    ss->x_i = x_i;
    ss->c = c;
    ss->z = z;

    tc_clear_bytes(buffer);

    return ss;
}

key_metainfo_t *tc_deserialize_key_metainfo(const char *b64) {
    bytes_t *buffer = tc_b64_bytes(b64);
    void *p =buffer;

    uint16_t version;
    DESERIALIZE_SHORT(version, p);

    bytes_t *pk;
    DESERIALIZE_BYTES(pk, p);

    uint16_t k;
    DESERIALIZE_SHORT(k, p);

    uint16_t l;
    DESERIALIZE_SHORT(l, p);

    bytes_t *vk_v;
    DESERIALIZE_BYTES(vk_v, p);

    key_metainfo_t * kmi = tc_init_key_meta_info(0, k, l);
    // We have to do this here, because init_key_meta_info initializes the vk_i array.
    for(int i=0; i<l; i++){
        bytes_t *v = kmi->vk_i + i;
        DESERIALIZE_BYTES(v, p);
    }

    p = pk->data;
    bytes_t *n;
    DESERIALIZE_BYTES(n, p);

    bytes_t *e;
    DESERIALIZE_BYTES(e, p);

    bytes_t *m;
    DESERIALIZE_BYTES(m, p);

    kmi->public_key->n = n;
    kmi->public_key->e = e;
    kmi->public_key->m = m;
    kmi->k = k;
    kmi->l = l;
    kmi->vk_v = vk_v;

    tc_clear_bytes(buffer);
    return kmi;
}
