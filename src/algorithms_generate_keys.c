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
    static const int c = 25; /* Number of Miller-Rabbin tests */

    mpz_t p, q, r, t1;
    mpz_inits(p, q, r, t1, NULL);
    int q_composite, r_composite;

    do {
	random_prime(p, bit_len, random);
	mpz_sub_ui(t1, p, 1);
	mpz_fdiv_q_ui(q, t1, 2);

	mpz_mul_ui(t1, p, 2);
	mpz_add_ui(r, t1, 1);

	/* r > p > q */

	q_composite = mpz_probab_prime_p(q, c) == 0;
	r_composite = mpz_probab_prime_p(r, c) == 0;
    } while (q_composite && r_composite);

    mpz_set(out, q_composite ? r : p);

    mpz_clears(p, q, r, t1, NULL);
}

/**
 * Generates ll shares, with a threshold of k.
 *
 * \param out a key share array with space for at least info->l shares, without initialization.
 * \param info a pointer to the meta info of the key set to be generated
 * \param public_key a pointer to a initialized but not defined public_key
 */
key_share_t **tc_generate_keys(key_metainfo_t **out, size_t bit_size, uint16_t k, uint16_t l) {

    /* Preconditions */
    assert(out != NULL);
    assert(bit_size >= 512 && bit_size <= 8192);
    assert(0 < k);
    assert(k <= l);
    assert(l / 2 + 1 <= k);

    key_metainfo_t *info = *out = tc_init_key_metainfo(k, l);
    key_share_t **ks = tc_init_key_shares(info);

    static const int F4 = 65537; // Fermat fourth number.

    size_t prime_size = bit_size / 2;

    mpz_t pr, qr, p, q, d, e, ll, m, n, delta_inv;
    mpz_inits(pr, qr, p, q, d, e, ll, m, n, delta_inv, NULL);

    generate_safe_prime(p, prime_size, random_dev);
    generate_safe_prime(q, prime_size, random_dev);

    // p' = (p-1)/2
    mpz_sub_ui(pr, p, 1);
    mpz_fdiv_q_ui(pr, pr, 2);

    // q' = (q-1)/2
    mpz_sub_ui(qr, q, 1);
    mpz_fdiv_q_ui(qr, qr, 2);

    // n = p * q, m = p' * q'
    mpz_mul(n, p, q);
    mpz_mul(m, pr, qr);
    TC_MPZ_TO_BYTES(info->public_key->n, n);

    mpz_set_ui(ll, l);
    if (mpz_cmp_ui(ll, F4) <= 0) { // group_size < F4
	mpz_set_ui(e, F4);
    } else {
	random_prime(e, mpz_sizeinbase(ll, 2) + 1, random_dev);
    }
    TC_MPZ_TO_BYTES(info->public_key->e, e);

    // d = e^{-1} mod m
    mpz_invert(d, e, m);

    mpz_t divisor, r, vk_v, vk_u, s_i, vk_i;
    mpz_inits(divisor, r, vk_v, vk_u, s_i, vk_i, NULL);
    do {
	random_dev(r, mpz_sizeinbase(n, 2));
	mpz_gcd(divisor, r, n);
    } while (mpz_cmp_ui(divisor, 1) != 0);
    mpz_powm_ui(vk_v, r, 2, n);
    TC_MPZ_TO_BYTES(info->vk_v, vk_v);

    do {
	random_dev(vk_u, mpz_sizeinbase(n, 2));
	mpz_mod(vk_u, vk_u, n);
    } while (mpz_jacobi(vk_u, n) != -1);
    TC_MPZ_TO_BYTES(info->vk_u, vk_u);

    mpz_fac_ui(delta_inv, l);
    mpz_invert(delta_inv, delta_inv, m);
    poly_t *poly = create_random_poly(d, info->k-1, m);
    for(int i=1; i <= info->l; i++) {
	key_share_t * key_share = ks[TC_ID_TO_INDEX(i)];
	key_share->id = i;
	poly_eval_ui(s_i, poly, i);
	
	mpz_mul(s_i, s_i, delta_inv);
	mpz_mod(s_i, s_i, m);

	TC_MPZ_TO_BYTES(key_share->s_i, s_i);
	TC_MPZ_TO_BYTES(key_share->n, n);

	mpz_powm(vk_i, vk_v, s_i, n);
	TC_MPZ_TO_BYTES(&info->vk_i[TC_ID_TO_INDEX(i)], vk_i);
    }
    mpz_clears(s_i, vk_i, divisor, r, vk_v, vk_u, NULL);
    clear_poly(poly);
    

    mpz_clears(pr, qr, p, q, d, e, ll, m, n, delta_inv, NULL);

    assert(ks != NULL);
#ifndef NDEBUG
    for (int i = 0; i < info->l; i++) {
	assert(ks[i] != NULL);
    }
#endif
    assert(*out != NULL);

    return ks;
}
