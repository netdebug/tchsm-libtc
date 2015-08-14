#include <assert.h>
#include <gmp.h>
#include <stdlib.h>

#include "mathutils.h"

/** GMP-based polynomial library **/

poly_t * create_random_poly(mpz_t d, int size, mpz_t m) {
  assert(size > 0 && mpz_sgn(m) > 0);
  poly_t * poly = malloc(sizeof(*poly));

  int bit_len = mpz_sizeinbase(m, 2) - 1;

  poly->size = size;
  mpz_t * coeff = malloc(size * sizeof(*coeff));

  mpz_init_set(coeff[0], d);
  for (int i = 1; i < size; i++) {
    mpz_init(coeff[i]);
    random_dev(coeff[i], bit_len);
    mpz_mod(coeff[i], coeff[i], m);
  }
  poly->coeff = coeff;

  assert(mpz_cmp(poly->coeff[0], d) == 0);
  #ifndef NDEBUG
  for (int i=1; i < size; i++){
      assert(mpz_cmp(poly->coeff[i], m) < 0);
  }
  #endif
  return poly;
}

void clear_poly(poly_t * poly) {
  int i;
  mpz_t * coeff = poly->coeff;

  for(i=0; i<poly->size; i++) {
    mpz_clear(coeff[i]);
  }
  free(coeff);

  poly->coeff = NULL; // To force segfaults...
  free(poly);
}

/* Horner's method */
void poly_eval(mpz_t rop, poly_t * poly, mpz_t x) {
  assert(poly != NULL);
  mpz_t * coeff = poly->coeff;
  int size = poly->size;

  mpz_t y;

  /* y = 0 */
  mpz_init(y);
  for (int k=size - 1; k >= 0; k--) {
    /* y = a_k + x*y */
    mpz_mul(y, y, x);
    mpz_add(y, y, coeff[k]);
  }

  mpz_set(rop, y);

  mpz_clear(y);

}

void poly_eval_ui(mpz_t rop, poly_t * poly, unsigned long op) {
  mpz_t x;
  mpz_init_set_ui(x, op);
  poly_eval(rop, poly, x);
  mpz_clear(x);
}

#ifndef NO_CHECK
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
#endif
