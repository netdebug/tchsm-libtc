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
#if (__GNU_MP_VERSION >= 5.0)
    mpz_inits(p, q, r, t1, NULL);
#else
    mpz_init(p);
    mpz_init(q);
    mpz_init(r);
    mpz_init(t1);
#endif
    int q_composite, r_composite;

    /* The random prime has to be at most 2 bits less than the
     * expected safe prime. The reason is that we try for
     * 2 * random_prime + 1 to be prime too. If that's prime,
     * the resulting safe prime may have 2 more bits. */
    int random_prime_bit_len = bit_len - 2;
    do {
	random_prime(p, random_prime_bit_len, random);
	mpz_sub_ui(t1, p, 1);
	mpz_fdiv_q_ui(q, t1, 2);

	mpz_mul_ui(t1, p, 2);
	mpz_add_ui(r, t1, 1);

	/* r > p > q */

	q_composite = mpz_probab_prime_p(q, c) == 0;
	r_composite = mpz_probab_prime_p(r, c) == 0;
    } while (q_composite && r_composite);

    mpz_set(out, q_composite ? r : p);

#if (__GNU_MP_VERSION >= 5.0)
    mpz_clears(p, q, r, t1, NULL);
#else
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(r);
    mpz_clear(t1);
#endif
}

/**
 * Generates ll shares, with a threshold of k.
 */
key_share_t **tc_generate_keys(key_metainfo_t **out, size_t bit_size, uint16_t k, uint16_t l, bytes_t *public_e) {
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

    mpz_t pr, qr, p, q, d, e, ll, m, n, delta_inv, divisor, r, vk_v, vk_u, s_i, vk_i;
#if (__GNU_MP_VERSION >= 5.0)
    mpz_inits(pr, qr, p, q, d, e, ll, m, n, delta_inv, divisor, r, vk_v, vk_u, s_i, vk_i, NULL);
#else
    mpz_init(pr);
    mpz_init(qr);
    mpz_init(p);
    mpz_init(q);
    mpz_init(d);
    mpz_init(e);
    mpz_init(ll);
    mpz_init(m);
    mpz_init(n);
    mpz_init(delta_inv);
    mpz_init(divisor);
    mpz_init(r);
    mpz_init(vk_v);
    mpz_init(vk_u);
    mpz_init(s_i);
    mpz_init(vk_i);
#endif

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

    int e_set = 0;
    if (public_e != NULL) {
        TC_BYTES_TO_MPZ(e, public_e);
        if (mpz_probab_prime_p(e, 25) && mpz_cmp(ll, e) < 0) {
            e_set = !e_set;
        }
    }

    if (!e_set){
        mpz_set_ui(e, F4); // l is always less than 65537 (l is an uint16_t)
    }

    TC_MPZ_TO_BYTES(info->public_key->e, e);

    // d = e^{-1} mod m
    mpz_invert(d, e, m);

    // Generate v
    do {
	random_dev(r, mpz_sizeinbase(n, 2));
	mpz_gcd(divisor, r, n);
    } while (mpz_cmp_ui(divisor, 1) != 0);
    mpz_powm_ui(vk_v, r, 2, n);
    TC_MPZ_TO_BYTES(info->vk_v, vk_v);

    // Generate u
    do {
	random_dev(vk_u, mpz_sizeinbase(n, 2));
	mpz_mod(vk_u, vk_u, n);
    } while (mpz_jacobi(vk_u, n) != -1);
    TC_MPZ_TO_BYTES(info->vk_u, vk_u);

    // Delta = l!
    mpz_fac_ui(delta_inv, l);
    mpz_invert(delta_inv, delta_inv, m);

    // Generate Polynomial with random coefficients
    poly_t *poly = create_random_poly(d, info->k-1, m);

    // Calculate Key Shares
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

    clear_poly(poly);
#if (__GNU_MP_VERSION >= 5.0)
    mpz_clears(pr, qr, p, q, d, e, ll, m, n, delta_inv, divisor, r, vk_v, vk_u, s_i, vk_i, NULL);
#else
    mpz_clear(pr);
    mpz_clear(qr);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(d);
    mpz_clear(e);
    mpz_clear(ll);
    mpz_clear(m);
    mpz_clear(n);
    mpz_clear(delta_inv);
    mpz_clear(divisor);
    mpz_clear(r);
    mpz_clear(vk_v);
    mpz_clear(vk_u);
    mpz_clear(s_i);
    mpz_clear(vk_i);
#endif

    assert(ks != NULL);
#ifndef NDEBUG
    for (int i = 0; i < info->l; i++) {
	assert(ks[i] != NULL);
    }
#endif
    assert(*out != NULL);

    return ks;
}
