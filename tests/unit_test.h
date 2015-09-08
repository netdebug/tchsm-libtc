#ifndef UNIT_TEST_H
#define UNIT_TEST_H
typedef struct TCase TCase;
TCase *tc_test_case_algorithms_generate_keys_c();
TCase *tc_test_case_algorithms_join_signatures_c();
TCase *tc_test_case_poly_c();
TCase *tc_test_case_serialization();
TCase *tc_test_case_system_test();
TCase *tc_test_case_base64();
#endif
