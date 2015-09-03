#include <assert.h>
#include <gmp.h>
#include <stdio.h>

#include "mathutils.h"
#include "tc.h"
#include "tc_internal.h"


#include <check.h>

void generate_safe_prime(mpz_t out, int bit_len, random_fn random);

START_TEST(test_generate_safe_prime)
    {
        mpz_t p, q;
        mpz_inits(p, q, NULL);
        size_t key_size = 512;
        generate_safe_prime(p, key_size, random_dev);
        mpz_sub_ui(q, p, 1);
        mpz_fdiv_q_ui(q, q, 2);

        size_t p_size = mpz_sizeinbase(p, 2);

        ck_assert_msg(p_size >= key_size, "p_size: %zu, key_size: %zu\n", p_size, key_size);
        ck_assert(mpz_probab_prime_p(p, 25));
        ck_assert(mpz_probab_prime_p(q, 25));
        mpz_clears(p, q, NULL);
    }
END_TEST

START_TEST(test_verify_invert)
    {
        mpz_t p, q, p_, q_, m, e, d, r;
        mpz_inits(p, q, p_, q_, m, e, d, r, NULL);
        generate_safe_prime(p, 256, random_dev);
        generate_safe_prime(q, 256, random_dev);

        mpz_sub_ui(p_, p, 1);
        mpz_fdiv_q_ui(p_, p_, 2);
        mpz_sub_ui(q_, q, 1);
        mpz_fdiv_q_ui(q_, q_, 2);

        mpz_mul(m, p_, q_);

        mpz_set_ui(e, 65537);

        mpz_invert(d, e, m);

        mpz_mul(r, d, e);
        mpz_mod(r, r, m);

        ck_assert(mpz_cmp_si(r, 1) == 0);

        mpz_clears(p, q, p_, q_, m, e, d, r, NULL);
    }
END_TEST

TCase *tc_test_case_algorithms_generate_keys_c() {
    TCase *tc = tcase_create("algorithms_generate_keys.c");
    tcase_add_test(tc, test_generate_safe_prime);
    tcase_add_test(tc, test_verify_invert);
    return tc;
}
