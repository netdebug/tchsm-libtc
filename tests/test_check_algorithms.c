/***
 * Unit and integration tests.
 * TODO: We need to test failure cases.
 */
#define _POSIX_C_SOURCE 200809L

#include "tc.h"
#include "tc_internal.h"
#include "unit_test.h"

#include <stdlib.h>
#include <string.h>
#include <check.h>

#if 0
static int bytes_cmp(bytes_t *a, bytes_t *b) {
    return memcmp(a->data, b->data, a->data_len);
}
static int key_metainfo_eq(key_metainfo_t *a, key_metainfo_t *b) {
    if (bytes_cmp(a->public_key->n, b->public_key->n) != 0) {
        return 0;
    }
    if (bytes_cmp(a->public_key->e, b->public_key->e) != 0) {
        return 0;
    }
    if (a->k != b->k) {
        return 0;
    }
    if (a->l != b->l) {
        return 0;
    }
    if (bytes_cmp(a->vk_v, b->vk_v) != 0) {
        return 0;
    }


    return 1;
}
#endif

START_TEST(test_complete_sign){

    /* First generate the keys */
    key_metainfo_t * info;
    key_share_t ** shares = tc_generate_keys(&info, 1024, 3, 5, NULL);

    /* Then serialize them */
    int l = tc_key_meta_info_l(info);
    char * serialized_shares[l];
    char * serialized_info;
    for(int i=0; i<l; i++) {
        serialized_shares[i] = tc_serialize_key_share(shares[i]);
    }    
    serialized_info = tc_serialize_key_metainfo(info);
    
    /* And finally clear the original ones */
    tc_clear_key_shares(shares, info);

    const char * message = "Hello world!";
    bytes_t * doc = tc_init_bytes(strdup(message), strlen(message));
    bytes_t * doc_pkcs1 = tc_prepare_document(doc, TC_SHA256, info);
    
    char * serialized_signatures[l];

    for (int i=0; i<l; i++) {
        key_share_t * share = tc_deserialize_key_share(serialized_shares[i]);	
        key_metainfo_t * minfo = tc_deserialize_key_metainfo(serialized_info);
	
        
        signature_share_t * signature = tc_node_sign(share, doc_pkcs1, minfo); 
        int verify = tc_verify_signature(signature, doc_pkcs1, minfo);
        ck_assert_msg(verify, "1st Signature Share verification.");
        serialized_signatures[i] = tc_serialize_signature_share(signature);
	tc_clear_signature_share(signature);
        tc_clear_key_share(share);
        tc_clear_key_metainfo(minfo);
    }

    signature_share_t * signatures[l];
    for (int i=0; i<l; i++) {
        signatures[i] = tc_deserialize_signature_share(serialized_signatures[i]);

	int verify = tc_verify_signature(signatures[i], doc_pkcs1, info);
        ck_assert_msg(verify, "2nd Signature Share verification.");
    }

    bytes_t * rsa_signature = tc_join_signatures((void*) signatures, doc_pkcs1, info);

    int verify = tc_rsa_verify(rsa_signature, doc, info, TC_SHA256);
    ck_assert_msg(verify, "RSA Signature verification.");

    tc_clear_bytes(rsa_signature);
    for(int i=0; i<l; i++) {
	free(serialized_signatures[i]);
        tc_clear_signature_share(signatures[i]);
        free(serialized_shares[i]);
    }
    free(serialized_info);
    tc_clear_key_metainfo(info);
    tc_clear_bytes(doc);
    tc_clear_bytes(doc_pkcs1);
}
END_TEST

TCase *tc_test_case_system_test() {
    TCase *tc = tcase_create("System test");
    tcase_set_timeout(tc, 500);
    tcase_add_test(tc, test_complete_sign);
    return tc;
}


