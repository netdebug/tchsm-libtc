/***
 * Unit and integration tests.
 * TODO: We need to test failure cases.
 */
#define _POSIX_C_SOURCE 200809L

#include "tc.h"
#include "tc_internal.h"
#include "unit_test.h"

#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>

static int bytes_cmp(bytes_t *a, bytes_t *b) {
    return memcmp(a->data, b->data, a->data_len);
}

static void complete_sign(int threshold, int nodes, size_t key_size, int expected_verify) {

    /* First generate the keys */
    key_metainfo_t * info;
    key_share_t ** shares = tc_generate_keys(&info, key_size, threshold, nodes, NULL);

    /* Then serialize them */
    int l = tc_key_meta_info_l(info);
    ck_assert_int_eq(l, nodes);
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
    ck_assert_msg(verify == expected_verify, "RSA Signature verification.");

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

START_TEST(test_complete_sign_1_1){
    complete_sign(1, 1, 512, 0);
}
END_TEST

START_TEST(test_complete_sign){
    for (int nodes=2; nodes <= 11; nodes += 3) {
	complete_sign(nodes/2 + 1, nodes, 512, 1);
	complete_sign(nodes, nodes, 512, 1);
    }
}
END_TEST

START_TEST(test_endianess){
    /* Test that output is Big Endian */
    uint8_t data[] = { 1, 0, 0 };
    uint32_t data_len = sizeof(data)/sizeof(data[0]);
    bytes_t bs1 = { .data = data, .data_len = data_len };

    mpz_t number;
    mpz_init(number);
    
    TC_BYTES_TO_MPZ(number, &bs1);
    ck_assert(mpz_cmp_ui(number, 65536) == 0);
    
    mpz_set_ui(number, 65536);
    bytes_t bs2;
    TC_MPZ_TO_BYTES(&bs2, number);

    ck_assert(bytes_cmp(&bs1, &bs2) == 0);
    mpz_clear(number);
    free(bs2.data);
}
END_TEST

TCase *tc_test_case_system_test() {
    TCase *tc = tcase_create("System test");
    tcase_set_timeout(tc, 500);
    tcase_add_test(tc, test_complete_sign_1_1);
    tcase_add_test(tc, test_complete_sign);
    tcase_add_test(tc, test_endianess);
    return tc;
}


