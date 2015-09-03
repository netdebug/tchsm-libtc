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

Suite * algorithms_suite(void)
{
    Suite *s = suite_create("Algorithms");

    /* Core test case */
    suite_add_tcase(s, tc_test_case_system_test());
    suite_add_tcase(s, tc_test_case_algorithms_generate_keys_c());
    suite_add_tcase(s, tc_test_case_algorithms_join_signatures_c());
    suite_add_tcase(s, tc_test_case_poly_c());
    suite_add_tcase(s, tc_test_case_serialization());

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
