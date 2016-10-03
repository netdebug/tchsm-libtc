#include <gmp.h>

#include "mathutils.h"
#include <check.h>
#include <stdio.h>

void generate_safe_prime(mpz_t out, int bit_len, random_fn random);

START_TEST(test_prime_size)
    {
        mpz_t p;
        mpz_init(p);
        size_t size = 512;

        for (int i=0; i<50; i++) {
            generate_safe_prime(p, size, random_dev);
            size_t p_size = mpz_sizeinbase(p, 2);
            fprintf(stderr, "p_size: %zu, key_size: %zu\n", p_size, size);
            // ck_assert_msg(p_size >= size, "p_size: %zu, key_size: %zu\n", p_size, size);
        }
        mpz_clear(p);
    }
END_TEST

START_TEST(test_generate_safe_prime)
    {
        mpz_t p, q;
        mpz_init(p);
        mpz_init(q);
        size_t key_size = 512;

        generate_safe_prime(p, key_size, random_dev);

        mpz_sub_ui(q, p, 1);
        mpz_fdiv_q_ui(q, q, 2);

        ck_assert(mpz_probab_prime_p(p, 25));
        ck_assert(mpz_probab_prime_p(q, 25));

        fprintf(stderr, "p_size: %zu, q_size: %zu\n", mpz_sizeinbase(p, 2), mpz_sizeinbase(q, 2));
        mpz_clears(p, q, NULL);
    }
END_TEST

START_TEST(test_verify_invert)
    {
        mpz_t p, q, p_, q_, m, e, d, r;
#if (__GNU_MP_VERSION >= 5.0)
        mpz_inits(p, q, p_, q_, m, e, d, r, NULL);
#else
        mpz_init(p);
        mpz_init(q);
        mpz_init(p_);
        mpz_init(q_);
        mpz_init(m);
        mpz_init(e);
        mpz_init(d);
        mpz_init(r);
#endif
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

#if (__GNU_MP_VERSION >= 5.0)
        mpz_clears(p, q, p_, q_, m, e, d, r, NULL);
#else
        mpz_clear(p);
        mpz_clear(q);
        mpz_clear(p_);
        mpz_clear(q_);
        mpz_clear(m);
        mpz_clear(e);
        mpz_clear(d);
        mpz_clear(r);
#endif
    }
END_TEST

TCase *tc_test_case_algorithms_generate_keys_c() {
    TCase *tc = tcase_create("algorithms_generate_keys.c");
    // tcase_add_test(tc, test_prime_size);
    tcase_add_test(tc, test_generate_safe_prime);
    // tcase_add_test(tc, test_verify_invert);
    tcase_set_timeout(tc, 320);
    return tc;
}
