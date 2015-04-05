#include "algorithms.h"
#include <assert.h>
#include <stdlib.h>

// Generates info->l shares, with a threshold of k.

/**
  * \param out a key share array with space for at least info->l shares, without initialization.
  * \param info a pointer to the meta info of the key set to be generated
  * \param public_key a pointer to a initialized but not defined public_key
  */
void generate_keys(key_share_t * out, key_meta_info_t * info, public_key_t * public_key) {
    /* Preconditions */
    assert(info != NULL && public_key != NULL && info->k < info-> l);
    static const int F4 = 65537;

    int prime_size = info->bit_size / 2;

    mpz_t pr, qr, p, q, d, e, group_size, m, n;
    mpz_inits(pr, qr, p, q, d, e, group_size, m, n, NULL);

    generate_safe_prime(p, prime_size, random_dev);
    generate_safe_prime(q, prime_size, random_dev);

    mpz_sub_ui(pr, p, 1);
    mpz_fdiv_q_ui(pr, pr, 2);

    mpz_sub_ui(qr, q, 1);
    mpz_fdiv_q_ui(qr, qr, 2);

    mpz_mul(m, pr, qr);
    mpz_mul(n, p, q);

    mpz_set_ui(group_size, info->l);
    if(mpz_cmp_ui(group_size, F4) <= 0) { // group_size < F4
        mpz_set_ui(e, F4);

    } else {
        random_prime(e, mpz_sizeinbase(group_size, 2) + 1, random_dev);        
    }

    mpz_set(public_key->n, n);
    mpz_set(public_key->e, e);
    mpz_set(public_key->m, m);

    mpz_invert(d, e, m);

    // generate info->l shares.
    generate_key_shares(out, info, n, d, m); 
    generate_group_verifier(info, n);
    generate_share_verifiers(info, out);

    mpz_clears(pr, qr, p, q, d, e, group_size, m, n, NULL);
}

void generate_safe_prime(mpz_t out, int bit_len, random_fn random) {
    static const int c = 25;

    mpz_t p, q, r;
    mpz_inits(p,q,r,NULL);
    int q_composite, r_composite;

    do {
        random_prime(p, bit_len, random);
        mpz_sub_ui(q, p, 1);
        mpz_fdiv_q_ui(q, q, 2);

        mpz_mul_ui(r, p, 2);
        mpz_add_ui(r, r, 1);

        q_composite = mpz_probab_prime_p(q, c) == 0;
        r_composite = mpz_probab_prime_p(r, c) == 0;
    } while (q_composite && r_composite);

    mpz_set(out, q_composite? r : p);

    mpz_clears(p,q,r,NULL);
}

void generate_group_verifier(key_meta_info_t * info, mpz_t n) {
    mpz_t rand, d, j;
    mpz_inits(info->vk_v, info->vk_u, rand, d, j, NULL);

    /* Calculate v */
    do {
        random_dev(rand, mpz_sizeinbase(n, 2));
        mpz_gcd(d, rand, n);
    } while(mpz_cmp_ui(d, 1) != 0);

    mpz_powm_ui(info->vk_v, rand, 2, n);

    /* Calculate u */
    do {
        random_dev(rand, mpz_sizeinbase(n,2));
    } while(mpz_jacobi(rand,n) != -1);

    mpz_set(info->vk_u, rand);

    mpz_clears(rand, d, j, NULL);

}

/* Have to be used after group verifier generation */
void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares) {
    info->vk_i = malloc(info->l * sizeof(*(info->vk_i)));
    for (int i=0; i<info->l; i++) {
        mpz_init(info->vk_i[i]);
        mpz_powm(info->vk_i[i], info->vk_v, shares[i].s_i, shares[i].n);
    }
}

void generate_key_shares(key_share_t * shares, const key_meta_info_t * info, mpz_t n, mpz_t d, mpz_t m){ 
    // static const long L1 = 128L; // Security parameter.

    int i, exists_inv;
    mpz_t rand, delta, delta_inv;
    mpz_inits(rand, delta, delta_inv, NULL);

    mpz_fac_ui(delta, info->l);
    exists_inv = mpz_invert(delta_inv, delta, m);

    poly_t * poly = create_random_poly(d, info->k - 1, m);

    for(i=0; i<info->l; i++) {
        // shares[0] => s_1...
        poly_eval_ui(shares[i].s_i, poly, i+1);
        if(exists_inv) {
            mpz_mul(shares[i].s_i, shares[i].s_i, delta_inv);
        } else {
            mpz_fdiv_q(shares[i].s_i, shares[i].s_i, delta);
        }
        mpz_mod(shares[i].s_i, shares[i].s_i, m);
        mpz_set(shares[i].n, n);
    }

    clear_poly(poly);
    mpz_clears(rand, delta, NULL);
}
