/***
 * Unit and integration tests.
 * TODO: We need to test failure cases.
 */
#include "tc.h"
#include "tc_internal.h"
#include "mathutils.h"
#include "unit_test.h"

#include <stdbool.h>
#include <gmp.h>
#include <mhash.h>

#include <check.h>

#include <stdlib.h>

START_TEST(test_complete_sign){
    key_meta_info_t * info;
    key_share_t ** shares = tc_generate_keys(&info, 1024, 3, 5);

    const char * message = "Hola mundo";
    bytes_t * doc = tc_init_bytes((byte *) strdup(message), strlen(message));
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
    tc_clear_key_meta_info(info);
}
END_TEST

Suite * algorithms_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Algorithms");

    /* Core test case */
    tc_core = tcase_create("Integration");
    tcase_add_test(tc_core, test_complete_sign);
    tcase_set_timeout(tc_core, 240);
    suite_add_tcase(s, tc_core);

    suite_add_tcase(s, tc_test_case_algorithms_generate_keys_c());
    suite_add_tcase(s, tc_test_case_algorithms_join_signatures_c());
    suite_add_tcase(s, tc_test_case_poly_c());

    return s;
}

int main() {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = algorithms_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
