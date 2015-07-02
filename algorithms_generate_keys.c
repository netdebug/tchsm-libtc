#include "tc.h"
#include "mathutils.h"
#include <assert.h>
#include <stdlib.h>

/* Fast safe prime generation,
 * if it finds a prime it tries the next probably safe prime or the previous */
void generate_safe_prime(mpz_t out, int bit_len, random_fn random) {
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

static void generate_group_verifier(key_meta_info_t * info, mpz_t n) {
    mpz_t rand, d, j;
    mpz_inits(info->vk_v, rand, d, j, NULL);

    /* Calculate v */
    do {
        random_dev(rand, mpz_sizeinbase(n, 2));
        mpz_gcd(d, rand, n);
    } while(mpz_cmp_ui(d, 1) != 0);

    mpz_powm_ui(info->vk_v, rand, 2, n);

    mpz_clears(rand, d, j, NULL);

}

/* Have to be used after group verifier generation */
static void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares) {
    info->vk_i = malloc(info->l * sizeof(*(info->vk_i)));
    for (int i=0; i<info->l; i++) {
        mpz_init(info->vk_i[i]);
        mpz_powm(info->vk_i[i], info->vk_v, shares[i].s_i, shares[i].n);
    }
}

static void generate_key_shares(key_share_t * shares, const key_meta_info_t * info, mpz_t n, mpz_t a0, mpz_t m){ 
    int i; 
    mpz_t t1;
    mpz_init(t1);

    poly_t * poly = create_random_poly(a0, info->k - 1, m);

    for(i=1; i<=info->l; i++) {
        shares[TC_ID_TO_INDEX(i)].id = i;
        poly_eval_ui(t1, poly, i);
        mpz_mod(shares[TC_ID_TO_INDEX(i)].s_i, t1, m);
        mpz_set(shares[TC_ID_TO_INDEX(i)].n, n);
    }

    clear_poly(poly);
    mpz_clear(t1);
}
// Generates info->l shares, with a threshold of k.

/**
  * \param out a key share array with space for at least info->l shares, without initialization.
  * \param info a pointer to the meta info of the key set to be generated
  * \param public_key a pointer to a initialized but not defined public_key
  */
tc_error_t tc_generate_keys(key_share_t * out, key_meta_info_t * info) {
    /* Preconditions */
    assert(info != NULL && info->public_key!= NULL && info->k < info-> l);
    static const int F4 = 65537;

    int prime_size = info->bit_size / 2;

    mpz_t pr, qr, p, q, d, e, l, m, n, t1;
    mpz_inits(pr, qr, p, q, d, e, l, m, n, t1, NULL);

    generate_safe_prime(p, prime_size, random_dev);
    generate_safe_prime(q, prime_size, random_dev);

    mpz_sub_ui(t1, p, 1);
    mpz_fdiv_q_ui(pr, t1, 2);

    mpz_sub_ui(t1, q, 1);
    mpz_fdiv_q_ui(qr, t1, 2);

    mpz_mul(n, p, q);
    mpz_mul(m, pr, qr);

    mpz_set_ui(l, info->l);
    if(mpz_cmp_ui(l, F4) <= 0) { // group_size < F4
        mpz_set_ui(e, F4);
    } else {
        random_prime(e, mpz_sizeinbase(l, 2) + 1, random_dev);        
    }

    mpz_set(info->public_key->n, n);
    mpz_set(info->public_key->e, e);
    mpz_set(info->public_key->m, m);

    mpz_invert(d, e, m);

    // generate info->l shares.
    generate_key_shares(out, info, n, d, m); 
    generate_group_verifier(info, n);
    generate_share_verifiers(info, out);

    mpz_clears(pr, qr, p, q, d, e, l, m, n, t1, NULL);

    return TC_OK;
}
