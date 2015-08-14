#include <assert.h>
#include <gmp.h>
#include <stdio.h>

#include "mathutils.h"
#include "tc.h"
#include "tc_internal.h"


/* Fast safe prime generation,
 * if it finds a prime it tries the next probably safe prime or the previous */
void generate_safe_prime(mpz_t out, int bit_len, random_fn random) {
	assert(random != NULL);
	assert(bit_len >= 256 && bit_len <= 4096);
	static const int c = 25; /* Number of Miller-Rabbin tests */

	mpz_t p, q, r, t1;
	mpz_inits(p,q,r,t1,NULL);
	int q_composite, r_composite;

	do {
		random_prime(p, bit_len, random);
		mpz_sub_ui(t1, p, 1);
		mpz_fdiv_q_ui(q, t1, 2);

		mpz_mul_ui(t1, p, 2);
		mpz_add_ui(r, t1, 1);

		q_composite = mpz_probab_prime_p(q, c) == 0;
		r_composite = mpz_probab_prime_p(r, c) == 0;
	} while (q_composite && r_composite);

	mpz_set(out, q_composite? r : p);

	mpz_clears(p,q,r,t1,NULL);
}

static void generate_group_verifier(key_meta_info_t * info) {
	mpz_t vk_v, rand, d, j, n;
	mpz_inits(vk_v, rand, d, j, n, NULL);

	TC_BYTES_TO_MPZ(n, info->public_key->n);

	/* Calculate v */
	do {
		random_dev(rand, mpz_sizeinbase(n, 2));
		mpz_gcd(d, rand, n);
	} while(mpz_cmp_ui(d, 1) != 0);

	mpz_powm_ui(vk_v, rand, 2, n);

	TC_MPZ_TO_BYTES(info->vk_v, vk_v);

	mpz_clears(vk_v, rand, d, j, n, NULL);
}

/* Have to be used after group verifier generation */
static void generate_share_verifiers(key_share_t ** shares, key_meta_info_t * info) {
	mpz_t vk_v, s_i, vk_i, n;
	mpz_inits(vk_v, s_i, vk_i, n, NULL);
	TC_BYTES_TO_MPZ(vk_v, info->vk_v);
	TC_BYTES_TO_MPZ(n, info->public_key->n);
	for (int i=0; i<info->l; i++) {
		TC_BYTES_TO_MPZ(s_i, shares[i]->s_i);
		mpz_powm(vk_i, vk_v, s_i, n);
		TC_MPZ_TO_BYTES(info->vk_i + i, vk_i);
	}
	mpz_clears(vk_v, s_i, vk_i, n, NULL);
}

static void generate_key_shares(key_share_t ** shares, const key_meta_info_t * info, mpz_t a0){ 
	int i;
	mpz_t t1, s_i, n, m;
	mpz_inits(t1, s_i, n, m, NULL);

	TC_BYTES_TO_MPZ(n, info->public_key->n);
	TC_BYTES_TO_MPZ(m, info->public_key->m);

	poly_t * poly = create_random_poly(a0, info->k - 1, m);

	for(i=1; i<=info->l; i++) {
		shares[TC_ID_TO_INDEX(i)]->id = i;
		poly_eval_ui(t1, poly, i);
		mpz_mod(s_i, t1, m);
		TC_MPZ_TO_BYTES(shares[TC_ID_TO_INDEX(i)]->s_i, s_i);
		TC_MPZ_TO_BYTES(shares[TC_ID_TO_INDEX(i)]->n, n);
	}

	clear_poly(poly);
	mpz_clears(t1, s_i, n, m, NULL);
}
// Generates info->l shares, with a threshold of k.

/**
 * \param out a key share array with space for at least info->l shares, without initialization.
 * \param info a pointer to the meta info of the key set to be generated
 * \param public_key a pointer to a initialized but not defined public_key
 */
key_share_t ** tc_generate_keys(key_meta_info_t ** out, int bit_size, int k, int ll){

	/* Preconditions */
	assert(out != NULL);
	assert(bit_size >= 512 && bit_size <= 8192);
	assert(0 < k);
	assert(k <= ll);
	assert(ll/2 + 1 <= k);

	key_meta_info_t * info = *out = tc_init_key_meta_info(bit_size, k, ll);
	key_share_t ** ks = tc_init_key_shares(info);

	static const int F4 = 65537;

	int prime_size = bit_size / 2;

	mpz_t pr, qr, p, q, d, e, l, m, n;
	mpz_inits(pr, qr, p, q, d, e, l, m, n, NULL);

	generate_safe_prime(p, prime_size, random_dev);
	generate_safe_prime(q, prime_size, random_dev);

	mpz_sub_ui(pr, p, 1);
	mpz_fdiv_q_ui(pr, pr, 2);

	mpz_sub_ui(qr, q, 1);
	mpz_fdiv_q_ui(qr, qr, 2);

	mpz_mul(n, p, q);
	mpz_mul(m, pr, qr);

	mpz_set_ui(l, ll);
	if(mpz_cmp_ui(l, F4) <= 0) { // group_size < F4
		mpz_set_ui(e, F4);
	} else {
		random_prime(e, mpz_sizeinbase(l, 2) + 1, random_dev);
	}

	TC_MPZ_TO_BYTES(info->public_key->n, n);
	TC_MPZ_TO_BYTES(info->public_key->e, e);
	TC_MPZ_TO_BYTES(info->public_key->m, m);

	mpz_invert(d, e, m);

	// generate info->l shares.
	generate_key_shares(ks, info, d);
	generate_group_verifier(info);
	generate_share_verifiers(ks, info);

	mpz_clears(pr, qr, p, q, d, e, l, m, n, NULL);

	assert(ks != NULL);
#ifndef NDEBUG
	for (int i=0; i<info->l; i++) {
		assert(ks[i] != NULL);
	}
#endif
	assert(*out != NULL);
	return ks;
}


#ifndef NO_CHECK
#include <check.h>
START_TEST(test_generate_safe_prime) {
    mpz_t p, q;
    mpz_inits(p,q,NULL);
    generate_safe_prime(p, 512, random_dev);
    mpz_sub_ui(q, p, 1);
    mpz_fdiv_q_ui(q, q, 2);

    ck_assert(mpz_probab_prime_p(p, 25));
    ck_assert(mpz_probab_prime_p(q, 25));
    mpz_clears(p,q,NULL);
}
END_TEST

START_TEST(test_verify_invert) {
    mpz_t p, q, p_, q_, m, e, d, r;
    mpz_inits(p,q, p_, q_, m, e, d, r, NULL);
    generate_safe_prime(p, 512, random_dev);
    generate_safe_prime(q, 512, random_dev);

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

    mpz_clears(p,q, p_, q_, m, e, d, r, NULL);
}
END_TEST

TCase * tc_test_case_algorithms_generate_keys_c() {
	TCase * tc = tcase_create("algorithms_generate_keys.c");
	tcase_add_test(tc, test_generate_safe_prime);
	tcase_add_test(tc, test_verify_invert);
	return tc;
}
#endif
