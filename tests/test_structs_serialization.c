#define _POSIX_C_SOURCE 200809L
#include "tc_internal.h"

#include <string.h>
#include <stdlib.h>
#include <check.h>

static int bytes_eq(bytes_t *a, bytes_t *b) {
    return (a->data_len == b->data_len) &&
        (memcmp(a->data, b->data, a->data_len) == 0);
}

START_TEST(test_serialization_key_share)
    {
        key_metainfo_t *info;
        key_share_t **shares = tc_generate_keys(&info, 512, 3, 5, NULL);

        char *share0_b64 = tc_serialize_key_share(shares[0]);
        key_share_t *share0 = tc_deserialize_key_share(share0_b64);

        ck_assert(shares[0]->id == share0->id);
        ck_assert(bytes_eq(shares[0]->n, share0->n));
        ck_assert(bytes_eq(shares[0]->s_i, share0->s_i));

        tc_clear_key_shares(shares, info);
        tc_clear_key_metainfo(info);
        tc_clear_key_share(share0);
        free(share0_b64);
    }
END_TEST

START_TEST(test_serialization_key_share_error) {
        key_metainfo_t *info;
        key_share_t **shares = tc_generate_keys(&info, 512, 3, 5, NULL);

        char *share0_b64 = tc_serialize_key_share(shares[0]);
        share0_b64[0] = '0';
        share0_b64[1] = '0';
        key_share_t *share0 = tc_deserialize_key_share(share0_b64);

        ck_assert_ptr_eq(share0, NULL);
        tc_clear_key_shares(shares, info);
        tc_clear_key_metainfo(info);
        free(share0_b64);
    }
END_TEST

START_TEST(test_serialization_signature_share)
    {
        key_metainfo_t *info;
        key_share_t **shares = tc_generate_keys(&info, 512, 3, 5, NULL);

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

        tc_clear_key_shares(shares, info);
        tc_clear_key_metainfo(info);
        tc_clear_bytes_n(doc, doc_pkcs1, NULL);
        tc_clear_signature_share(s);
        tc_clear_signature_share(new_s);
        free(signature_b64);
    }
END_TEST
START_TEST(test_serialization_key_metainfo)
    {
        key_metainfo_t *mi;
        key_share_t **shares = tc_generate_keys(&mi, 1024, 3, 5, NULL);

        char *mi_b64 = tc_serialize_key_metainfo(mi);
        key_metainfo_t *new_mi = tc_deserialize_key_metainfo(mi_b64);

        ck_assert(mi->k == new_mi->k);
        ck_assert(mi->l == new_mi->l);
        ck_assert(bytes_eq(mi->public_key->n, new_mi->public_key->n));
        ck_assert(bytes_eq(mi->public_key->e, new_mi->public_key->e));
        ck_assert(bytes_eq(mi->vk_v, new_mi->vk_v));
        for(int i=0; i<mi->l; i++) {
            bytes_t * a = mi->vk_i + i;
            bytes_t * b = new_mi->vk_i + i;
            ck_assert(bytes_eq(a, b));
        }

        tc_clear_key_shares(shares, mi);
        tc_clear_key_metainfo(mi);
        free(mi_b64);
        tc_clear_key_metainfo(new_mi);
    }
END_TEST


TCase *tc_test_case_serialization() {
    TCase *tc = tcase_create("poly.c");
    tcase_set_timeout(tc, 10);
    tcase_add_test(tc, test_serialization_key_share);
    tcase_add_test(tc, test_serialization_key_share_error);
    tcase_add_test(tc, test_serialization_signature_share);
    tcase_add_test(tc, test_serialization_key_metainfo);
    return tc;
}
