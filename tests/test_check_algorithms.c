/***
 * Unit and integration tests.
 * TODO: We need to test failure cases.
 */
#define _POSIX_C_SOURCE 200809L

#include "tc.h"
#include "tc_internal.h"
#include "mathutils.h"
#include "unit_test.h"

#include <string.h>
#include <stdbool.h>
#include <gmp.h>
#include <mhash.h>

#include <check.h>

#include <stdlib.h>

START_TEST(test_complete_sign){
    key_metainfo_t * info;
    key_share_t ** shares = tc_generate_keys(&info, 1024, 3, 5);

    const char * message = "Hola mundo";
    bytes_t * doc = tc_init_bytes(strdup(message), strlen(message));
    bytes_t * doc_pkcs1 = tc_prepare_document(doc, TC_SHA256, info);

    signature_share_t * signatures[info->l];

    for (int i=0; i<info->l; i++) {
        signatures[i] = tc_node_sign(shares[i], doc_pkcs1, info);
        bool verify = tc_verify_signature(signatures[i], doc_pkcs1, info);
        ck_assert_msg(verify, "Signature Share verification.");
    }

    bytes_t * signature = tc_join_signatures((void*) signatures, doc_pkcs1, info);

    bool verify = tc_rsa_verify(signature, doc, info, TC_SHA256);
    ck_assert_msg(verify, "RSA Signature verification.");

    tc_clear_bytes(signature);
    for(int i=0; i<info->l; i++) {
        tc_clear_signature_share(signatures[i]);
    }
    tc_clear_key_shares(shares, info);
    tc_clear_key_metainfo(info);
}
END_TEST

TCase *tc_test_case_system_test() {
    TCase *tc = tcase_create("System test");
    tcase_set_timeout(tc, 500);
    tcase_add_test(tc, test_complete_sign);
    return tc;
}


