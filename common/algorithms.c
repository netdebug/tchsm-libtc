#include <stdlib.h>
#include <stdio.h>
#include <gmp.h> 
#include <mhash.h>

#include "algorithms.h"

typedef unsigned char * byte;
static const unsigned int hash_len = 32; // sha256 => 256 bits => 32 bytes

static void generate_strong_prime(mpz_t out, int bit_len, random_fn random);
static key_share_t * generate_key_shares(const key_meta_info_t * info, mpz_t n, mpz_t d, mpz_t m);
static void lagrange_interpolation(mpz_t out, int i, int j, int n, signature_share_t ** signatures, mpz_t delta);
static void generate_group_verifier(key_meta_info_t * info, mpz_t n);
static void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares);

// Generates info->l shares, with a threshold of k.
key_share_t * generate_keys(key_meta_info_t * info, public_key_t * public_key) {
    static const int F4 = 65537;

    int prime_size = info->bit_size / 2;

    mpz_t pr, qr, p, q, d, e, group_size, m, n;
    mpz_inits(pr, qr, p, q, d, e, group_size, m, n, NULL);

    generate_strong_prime(p, prime_size, random_dev);
    generate_strong_prime(q, prime_size, random_dev);

    mpz_sub_ui(pr, p, 1);
    mpz_cdiv_q_ui(pr, pr, 2);

    mpz_sub_ui(qr, q, 1);
    mpz_cdiv_q_ui(qr, qr, 2);

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

    mpz_invert(d, e, m);

    // generate info->l shares.
    key_share_t * shares = generate_key_shares(info, n, d, m); 
    generate_group_verifier(info, n);
    generate_share_verifiers(info, shares);

    mpz_clears(pr, qr, p, q, d, e, group_size, m, n, NULL);

    return shares;
}

void clear_shares(key_share_t * shares, key_meta_info_t * info){
    int i;
    for(i=0; i<info->l; i++) {
        mpz_clears(shares[i].s_i, shares[i].n, NULL);
    }
    free(shares);
}

/**
  Signs the document with the nodes share.

  It is supposed that all integers are initialized. Even the ones in signatureshare_t out.
 */
void node_sign(signature_share_t * out, int node_id, const key_share_t * share, 
        const public_key_t * pk, const key_meta_info_t * info, 
        mpz_t doc) {

    mpz_t x, r, xi, xi2n, v_prime, x_tilde, x_prime, n;
    mpz_inits(x, r, xi, xi2n, v_prime, x_tilde, x_prime, n, NULL);
    mpz_set(n, pk->n);

    const unsigned long n_bits = mpz_sizeinbase(n, 2); // Bit size of the key.

    int j = mpz_jacobi(doc, n);
    if (j == 1) {
        mpz_mod(x, doc, n);
    } else if (j == -1) {
        mpz_powm(x, info->vk_u, pk->e, n);
        mpz_mul(x, x, doc);
        mpz_mod(x, x, n);
    }
    
    // x = doc % n;
    mpz_mod(x, doc, n);

    // xi = x^(2*share)
    mpz_mul_si(xi, share->s_i, 2);
    mpz_powm(xi, x, xi, n);

    // xi2n = xi^2 % n
    mpz_powm_ui(xi2n, xi, 2, n);

    // r = abs(random(bytes_len))
    random_dev(r, n_bits + 2*hash_len*8);

    // v_prime = v^r % n;
    mpz_powm(v_prime, info->vk_v, r, n);

    // x_tilde = x^4 % n
    mpz_powm_ui(x_tilde, x, 4, n);

    // x_prime = x_tilde^r % n
    mpz_powm(x_prime, x_tilde, r, n);

    // Every number calculated, now to bytes...
    size_t v_len, u_len, v_i_len, xi2n_len, v_prime_len, x_tilde_len, x_prime_len;


    void * v_bytes = mpz_export(NULL, &v_len, 1, 1, 1, 0, info->vk_v);
    void * u_bytes = mpz_export(NULL, &u_len, 1, 1, 1, 0, info->vk_u);
    void * x_tilde_bytes = mpz_export(NULL, &x_tilde_len, 1, 1, 1, 0, x_tilde);
    void * v_i_bytes = mpz_export(NULL, &v_i_len, 1, 1, 1, 0, info->vk_i[node_id]);
    void * xi2n_bytes = mpz_export(NULL, &xi2n_len, 1, 1, 1, 0, xi2n);
    void * v_prime_bytes = mpz_export(NULL, &v_prime_len, 1, 1, 1, 0, v_prime);
    void * x_prime_bytes = mpz_export(NULL, &x_prime_len, 1, 1, 1, 0, x_prime);

    // Initialization of the digest context

    unsigned char * hash = malloc(hash_len);
    MHASH sha = mhash_init(MHASH_SHA256);

    mhash(sha, v_bytes, v_len);
    mhash(sha, u_bytes, u_len);
    mhash(sha, x_tilde_bytes, x_tilde_len);
    mhash(sha, v_i_bytes, v_i_len);
    mhash(sha, xi2n_bytes, xi2n_len);
    mhash(sha, v_prime_bytes, v_prime_len);
    mhash(sha, x_prime_bytes, x_prime_len);

    mhash_deinit(sha, hash);

    void (*freefunc) (void *, size_t);
    mp_get_memory_functions (NULL, NULL, &freefunc);

    freefunc(v_bytes, v_len);
    freefunc(u_bytes, u_len);
    freefunc(x_tilde_bytes, x_tilde_len);
    freefunc(v_i_bytes, v_i_len);
    freefunc(xi2n_bytes, xi2n_len);
    freefunc(v_prime_bytes, v_prime_len);
    freefunc(x_prime_bytes, x_prime_len);

    mpz_import(out->c, hash_len, 1, 1, 1, 0, hash);
    free(hash);

    mpz_mul(out->z, out->c, share->s_i);
    mpz_add(out->z, out->z, r);

    mpz_set(out->signature, xi);
    out->id = node_id;

    mpz_clears(x, r, xi, xi2n, v_prime, x_tilde, x_prime, n, NULL);
}

static void generate_strong_prime(mpz_t out, int bit_len, random_fn random) {
    static const int certainty = 25;

    int i0_bit_len_target_value = 12;
    int j0_bit_len_target_value = 12;
    int t_bit_len = bit_len / 2 - i0_bit_len_target_value;

    mpz_t t, i0, a, b, c, d, r, i, p, s, p0, j0, j;
    mpz_inits(t, i0, a, b, c, d, r, i, p, s, p0, j0, j, NULL);

    random_prime(t, t_bit_len, random);

    int i0_bit_len = bit_len / 2 - mpz_sizeinbase(t, 2);
    mpz_setbit(i0, i0_bit_len - 1);

    mpz_mul_ui(a, t, 2);

    mpz_set(i, i0);

    do {
        mpz_mul(b, a, i);
        mpz_add_ui(r, b, 1);
        mpz_add_ui(i, i, 1);
    } while (mpz_probab_prime_p(r, certainty) == 0); // while is composite

    // outerloop
    do {
        // p0 = 2 * (s^(r-2) mod r) * s - 1
        int s_bit_len = bit_len - mpz_sizeinbase(r, 2) - j0_bit_len_target_value;
        random_prime(s, s_bit_len, random);
        mpz_mul_ui(a, s, 2);
        mpz_sub_ui(b, r, 2);
        mpz_powm(c, s, b, r);
        mpz_mul(d, c, a);
        mpz_sub_ui(p0, d, 1);

        // a = 2 * r * s
        mpz_mul_ui(a, r, 2);
        mpz_mul(a, a, s);

        mpz_set_ui(b, 0);
        mpz_setbit(b, bit_len - 1);
        mpz_sub(b, b, p0);

        mpz_mul_ui(c, r, 2);
        mpz_mul(c, c, s);

        mpz_fdiv_q(j0, b, c);

        mpz_mod(d, b, c);
        if(mpz_sgn(d) != 0) {
            mpz_add_ui(j0, j0, 1);
        }

        mpz_set(j, j0);

        do {
            // p = 2 * j * r * s + p0
            mpz_mul(p, a, j);
            mpz_add(p, p, p0);

            // j = j + 1
            mpz_add_ui(j, j, 1);
            if ( mpz_sizeinbase(p, 2) > bit_len ) {
                break;
            }

        } while (mpz_probab_prime_p(p, certainty) == 0);



    } while( mpz_sizeinbase(p, 2) != bit_len);

    mpz_set(out, p);

    mpz_clears(t, i0, a, b, c, d, r, i, p, s, p0, j0, j, NULL);
}

int verify_signature(const signature_share_t * signature, mpz_t doc,
        const public_key_t * pk, const key_meta_info_t * info, 
        int id) {

    mpz_t xtilde, xi2, v2prime, x2tilde, aux;
    mpz_inits(xtilde, xi2, v2prime, x2tilde, aux, NULL);

    mpz_powm_ui(xtilde, doc, 4, pk->n);
    mpz_powm_ui(xi2, doc, 2, pk->n);

    mpz_powm(aux, info->vk_v, signature->z, pk->n);
    mpz_powm(v2prime, info->vk_i[id], signature->c, pk->n);
    mpz_invert(v2prime, v2prime, pk->n);
    mpz_mul(v2prime, v2prime, aux);
    mpz_mod(v2prime, v2prime, pk->n);

    mpz_powm(aux, xtilde, signature->z, pk->n);
    mpz_mul_ui(x2tilde, signature->c, 2);
    mpz_powm(x2tilde, signature->signature, x2tilde, pk->n);
    mpz_invert(x2tilde, x2tilde, pk->n);
    mpz_mul(x2tilde, x2tilde, aux);
    mpz_mod(x2tilde, x2tilde, pk->n);


    size_t v_len, u_len, xtilde_len, v_i_len, xi2_len, v2prime_len, x2tilde_len;

    void * v_bytes = mpz_export(NULL, &v_len, 1, 1, 1, 0, info->vk_v);
    void * u_bytes = mpz_export(NULL, &u_len, 1, 1, 1, 0, info->vk_u);
    void * xtilde_bytes = mpz_export(NULL, &xtilde_len, 1, 1, 1, 0, xtilde);
    void * v_i_bytes = mpz_export(NULL, &v_i_len, 1, 1, 1, 0, info->vk_i[id]);
    void * xi2_bytes = mpz_export(NULL, &xi2_len, 1, 1, 1, 0, xi2);
    void * v2prime_bytes = mpz_export(NULL, &v2prime_len, 1, 1, 1, 0, v2prime);
    void * x2tilde_bytes = mpz_export(NULL, &x2tilde_len, 1, 1, 1, 0, x2tilde);

    // Initialization of the digest context

    unsigned char hash[hash_len];
    MHASH sha = mhash_init(MHASH_SHA256);

    mhash(sha, v_bytes, v_len);
    mhash(sha, u_bytes, u_len);
    mhash(sha, xtilde_bytes, xtilde_len);
    mhash(sha, v_i_bytes, v_i_len);
    mhash(sha, xi2_bytes, xi2_len);
    mhash(sha, v2prime_bytes, v2prime_len);
    mhash(sha, x2tilde_bytes, x2tilde_len);

    mhash_deinit(sha, hash);

    void (*freefunc) (void *, size_t);
    mp_get_memory_functions (NULL, NULL, &freefunc);

    freefunc(v_bytes, v_len);
    freefunc(u_bytes, u_len);
    freefunc(xtilde_bytes, xtilde_len);
    freefunc(v_i_bytes, v_i_len);
    freefunc(xi2_bytes, xi2_len);
    freefunc(v2prime_bytes, v2prime_len);
    freefunc(x2tilde_bytes, x2tilde_len);

    mpz_t h;
    mpz_import(h, hash_len, 1, 1, 1, 0, hash);
    int result = mpz_cmp(h, signature->c);
    
    mpz_clears(xtilde, xi2, v2prime, x2tilde, h, NULL);

    return result == 0;
}

/* All the signatures are valid before getting them here. 
 * k is the number of signatures in the array
 * TODO: verify if the array has less than info->l signatures.
 */
void join_signatures(mpz_t out, mpz_t document, 
        signature_share_t ** signatures, int k, 
        const public_key_t * pk, const key_meta_info_t * info){
    mpz_t e_prime;
    mpz_t w, lambda_k_2, delta;

    mpz_t aux, a, b, wa, xb, x;
    mpz_inits(aux, a, b, lambda_k_2, delta, x, NULL);

    mpz_init_set_si(e_prime, 4);

    /* Calculate w */
    mpz_init_set_si(w, 1);
    mpz_fac_ui(delta, info->l);

    for(int i = 0; i<k; i++) {
        int id = signatures[i]->id;
        lagrange_interpolation(lambda_k_2, 0, id, k, signatures, delta);
        mpz_mul_si(lambda_k_2, lambda_k_2, 2);
        mpz_powm(aux, signatures[i]->signature, lambda_k_2, pk->n);
        mpz_mul(w, w, aux);
    }

    mpz_mod(w, w, pk->n);

    mpz_gcdext(aux, a, b, pk->e, e_prime);

    mpz_powm(wa, w, a, pk->n);
    mpz_mod(x, document, pk->n);
    mpz_powm(xb, x, b, pk->n);

    mpz_mul(out, wa, xb);
    mpz_mod(out, out, pk->n);

    mpz_clears(aux, a, b, lambda_k_2, delta, w, e_prime, NULL);

}

static key_share_t * generate_key_shares(const key_meta_info_t * info, mpz_t n, mpz_t d, mpz_t m){ 
    static const long L1 = 128L; // Security parameter.

    int i;
    mpz_t rand, delta_inv;
    mpz_inits(rand, delta_inv, NULL);
    
    mpz_fac_ui(delta_inv, info->l);
    mpz_invert(delta_inv, delta_inv, m);

    int rand_bits = mpz_sizeinbase(n, 2) + L1 - mpz_sizeinbase(m, 2);
    key_share_t * shares = malloc(sizeof(*shares)*info->l);

    poly_t * poly = create_random_poly(d, info->k - 1, m);

    for(i=0; i<info->l; i++) {
        mpz_inits(shares[i].s_i, shares[i].n, NULL);
        poly_eval_ui(shares[i].s_i, poly, i+1);
        mpz_mul(shares[i].s_i, shares[i].s_i, delta_inv);

        random_dev(rand, rand_bits);
        mpz_mul(rand, rand, m);
        mpz_add(shares[i].s_i, shares[i].s_i, rand);

        mpz_set(shares[i].n, n);
    }

    clear_poly(poly);
    mpz_clears(rand, delta_inv, NULL);

    return shares;
}

static void generate_group_verifier(key_meta_info_t * info, mpz_t n) {
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

/* Should be used after group verifier generation */
static void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares) {
    info->vk_i = malloc(info->l * sizeof(*(info->vk_i)));
    for (int i=0; i<info->l; i++) {
        mpz_init(info->vk_i[i]);
        mpz_powm(info->vk_i[i], info->vk_v, shares[i].s_i, shares[i].n);
    }
} 

static void lagrange_interpolation(mpz_t out, int i, int j, int n, signature_share_t ** signatures, mpz_t delta) {
    mpz_set(out, delta);

    for (int k=0; k<n; k++) {
        if(signatures[k]->id != j) {
            mpz_mul_si(out, out, signatures[k]->id - i);
        }
    }

    for (int k=0; k<n; k++) {
        if(signatures[k]->id != j) {
            mpz_fdiv_q_ui(out, out, signatures[k]->id - j);
        }
    }

}
