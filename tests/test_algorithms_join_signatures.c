#include <gmp.h>
#include <check.h>

#include "tc.h"
#include "tc_internal.h"

void lagrange_interpolation(mpz_t out, int j, int k,
		const signature_share_t ** S, const mpz_t delta);


void lagrange_interpolation(mpz_t out, int j, int k, const signature_share_t ** S, const mpz_t delta);
START_TEST(test_lagrange_interpolation)
{
	const int k = 5;
	mpz_t out, delta;
	mpz_inits(out, delta, NULL);

	signature_share_t SS[] = { { .id = 1 }, { .id = 2 }, { .id = 3 },
			{ .id = 4 }, { .id = 5 } };
	signature_share_t const* S[] = { SS, SS + 1, SS + 2, SS + 3, SS + 4 };

	mpz_fac_ui(delta, k);

	lagrange_interpolation(out, 1, k, S, delta);
	ck_assert(mpz_cmp_si(out, 600) == 0);
	lagrange_interpolation(out, 2, k, S, delta);
	ck_assert(mpz_cmp_si(out, -1200) == 0);
	lagrange_interpolation(out, 3, k, S, delta);
	ck_assert(mpz_cmp_si(out, 1200) == 0);
	lagrange_interpolation(out, 4, k, S, delta);
	ck_assert(mpz_cmp_si(out, -600) == 0);
	lagrange_interpolation(out, 5, k, S, delta);
	ck_assert(mpz_cmp_si(out, 120) == 0);

	mpz_clears(out, delta, NULL);
}END_TEST

TCase * tc_test_case_algorithms_join_signatures_c() {
    TCase * tc = tcase_create("algorithms_join_signatures.c");
    tcase_add_test(tc, test_lagrange_interpolation);
    return tc;
}
