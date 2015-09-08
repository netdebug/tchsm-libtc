//
// Created by Francisco Cifuentes on 9/3/15.
//

#include <check.h>
#include <tc.h>
#include <stdlib.h>
#include <time.h>

START_TEST(encode)
    {
        bytes_t *bs = tc_init_bytes(strdup("Hello world"), 12);
        char *b64 = tc_bytes_b64(bs);

        ck_assert_msg(strcmp(b64, "SGVsbG8gd29ybGQA") == 0, "b64 error: %s\n", b64);

        free(b64);
        tc_clear_bytes(bs);
    }
END_TEST

START_TEST(decode)
    {
        char *b64 = "SGVsbG8gd29ybGQA";
        bytes_t *bs = tc_b64_bytes(b64);

        ck_assert_msg(strcmp("Hello world", bs->data) == 0, "b64 error: %s\n", b64);

        tc_clear_bytes(bs);
    }
END_TEST

START_TEST(encode_diff_original)
    {
        bytes_t *bs = tc_init_bytes(strdup("Hello world"), 12);
        char *b64 = tc_bytes_b64(bs);

        ck_assert_msg(memcmp(b64, bs->data, 12) != 0, "They are equal!\n");

        free(b64);
        tc_clear_bytes(bs);
    }
END_TEST

START_TEST(encode_decode)
    {
        srand((unsigned int)time(0));
        uint8_t b[10];
        for (int i=0; i<10; i++) {
            b[i] = (uint8_t) rand();
        }

        bytes_t bs = {.data = b, .data_len=10};
        char *b64 = tc_bytes_b64(&bs);

        bytes_t *new_bs = tc_b64_bytes(b64);
        memcmp(b, new_bs->data, 10);

        free(b64);
        tc_clear_bytes(new_bs);
    }
END_TEST

START_TEST(fail_case)
    {

    }
END_TEST

TCase *tc_test_case_base64() {
    TCase *tc = tcase_create("algorithms_generate_keys.c");

    tcase_add_test(tc, encode_diff_original);
    tcase_add_test(tc, encode);
    tcase_add_test(tc, decode);
    tcase_add_test(tc, encode_decode);
    tcase_add_test(tc, fail_case);

    return tc;
}
