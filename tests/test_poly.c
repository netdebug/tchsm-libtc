//
// Created by Francisco Cifuentes on 9/8/15.
//

#include "mathutils.h"
#include <check.h>

START_TEST(test_poly_eval){
    // Easy cases.

    mpz_t coeffs[10];
    mpz_t x, res, y;
    mpz_inits(x, res, y, NULL);
    for(int i=0; i<10; i++){
        mpz_init_set_ui(coeffs[i], 1);
    }
    poly_t p = {.coeff = coeffs, .size=10};

    mpz_set_ui(x, 1);
    poly_eval(res, &p, x);
    ck_assert(mpz_cmp_ui(res, 10) == 0);

    mpz_set_ui(x, 10);

    mpz_set_str(y, "1111111111", 0);
    poly_eval(res, &p, x);
    ck_assert(mpz_cmp(res, y) == 0);

    mpz_set_ui(x, 0);
    poly_eval(res, &p, x);
    ck_assert(mpz_cmp_ui(res, 1) == 0);
}
END_TEST

START_TEST(test_poly_eval_ui){
    // Easy cases.
    mpz_t res,y;
    mpz_inits(res,y,NULL);

    mpz_t coeffs[10];
    for(int i=0; i<10; i++){
        mpz_init_set_ui(coeffs[i], 1);
    }

    poly_t p = {.coeff = coeffs, .size=10};

    poly_eval_ui(res, &p, 1);
    ck_assert(mpz_cmp_si(res, 10) == 0);

    mpz_set_str(y, "1111111111", 0);
    poly_eval_ui(res, &p, 10);
    ck_assert(mpz_cmp(res, y) == 0);

    poly_eval_ui(res, &p, 0);
    ck_assert(mpz_cmp_si(res, 1) == 0);
    mpz_clears(res,y,NULL);
}
END_TEST

TCase * tc_test_case_poly_c() {
	TCase * tc = tcase_create("poly.c");
	tcase_add_test(tc, test_poly_eval);
	tcase_add_test(tc, test_poly_eval_ui);
	return tc;
}
