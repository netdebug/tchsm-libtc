#include <stdlib.h>
#include <stdio.h>
#include <gmp.h> 
#include <mhash.h>

#include "algorithms.h"

typedef unsigned char * byte;
static const unsigned int HASH_LEN = 32; // sha256 => 256 bits => 32 bytes

#if 0
static void generate_safe_prime(mpz_t out, int bit_len, random_fn random);
static key_share_t * generate_key_shares(const key_meta_info_t * info, mpz_t n, mpz_t d, mpz_t m);
static void lagrange_interpolation(mpz_t out, int i, int j, int n, const signature_share_t ** signatures, mpz_t delta);
static void generate_group_verifier(key_meta_info_t * info, mpz_t n);
static void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares);
#endif

// Generates info->l shares, with a threshold of k.
key_share_t * generate_keys(key_meta_info_t * info, public_key_t * public_key) {
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

    mpz_t x, r, xi, xi_2, v_prime, x_tilde, x_prime, n;
    mpz_inits(x, r, xi, xi_2, v_prime, x_tilde, x_prime, n, NULL);
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
    
    // xi = x^(2*share)
    mpz_mul_si(xi, share->s_i, 2);
    mpz_powm(xi, x, xi, n);

    // xi_2 = xi^2 
    mpz_powm_ui(xi_2, xi, 2, n);

    // r = abs(random(bytes_len))
    random_dev(r, n_bits + 2*HASH_LEN*8);

    // v_prime = v^r % n;
    mpz_powm(v_prime, info->vk_v, r, n);

    // x_tilde = x^4 % n
    mpz_powm_ui(x_tilde, x, 4, n);

    // x_prime = x_tilde^r % n
    mpz_powm(x_prime, x_tilde, r, n);

#if 0
    gmp_printf("v=%Zd\nx_tilde=%Zd\nvi=%Zd\nxi_2=%Zd\nv_prime=%Zd\nx_prime=%Zd\n\n", info->vk_v, x_tilde, info->vk_i[node_id], xi_2, v_prime, x_prime);
#endif

    // Every number calculated, now to bytes...
    size_t v_len, v_i_len, xi_2_len, v_prime_len, x_tilde_len, x_prime_len;


    void * v_bytes = mpz_export(NULL, &v_len, 1, 1, 1, 0, info->vk_v);
    void * x_tilde_bytes = mpz_export(NULL, &x_tilde_len, 1, 1, 1, 0, x_tilde);
    void * v_i_bytes = mpz_export(NULL, &v_i_len, 1, 1, 1, 0, info->vk_i[node_id]);
    void * xi_2_bytes = mpz_export(NULL, &xi_2_len, 1, 1, 1, 0, xi_2);
    void * v_prime_bytes = mpz_export(NULL, &v_prime_len, 1, 1, 1, 0, v_prime);
    void * x_prime_bytes = mpz_export(NULL, &x_prime_len, 1, 1, 1, 0, x_prime);

    // Initialization of the digest context

    unsigned char * hash = malloc(HASH_LEN);
    MHASH sha = mhash_init(MHASH_SHA256);

    mhash(sha, v_bytes, v_len);
    mhash(sha, x_tilde_bytes, x_tilde_len);
    mhash(sha, v_i_bytes, v_i_len);
    mhash(sha, xi_2_bytes, xi_2_len);
    mhash(sha, v_prime_bytes, v_prime_len);
    mhash(sha, x_prime_bytes, x_prime_len);

    mhash_deinit(sha, hash);

    void (*freefunc) (void *, size_t);
    mp_get_memory_functions (NULL, NULL, &freefunc);

    freefunc(v_bytes, v_len);
    freefunc(x_tilde_bytes, x_tilde_len);
    freefunc(v_i_bytes, v_i_len);
    freefunc(xi_2_bytes, xi_2_len);
    freefunc(v_prime_bytes, v_prime_len);
    freefunc(x_prime_bytes, x_prime_len);

    mpz_import(out->c, HASH_LEN, 1, 1, 1, 0, hash);
    mpz_mod(out->c, out->c, n);
    free(hash);

    mpz_mul(out->z, out->c, share->s_i);
    mpz_add(out->z, out->z, r);

    mpz_set(out->signature, xi);
    out->id = node_id;

    mpz_clears(x, r, xi, xi_2, v_prime, x_tilde, x_prime, n, NULL);
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

int verify_signature(const signature_share_t * signature, mpz_t doc,
        const public_key_t * pk, const key_meta_info_t * info, 
        int id) {

    mpz_t x, xi, xtilde, xi2, v_prime, x_prime, aux;
    mpz_inits(x, xtilde, xi2, v_prime, x_prime, aux, NULL);
    mpz_init_set(xi, signature->signature);
    
    if (mpz_jacobi(doc, pk->n) == 1) {
        mpz_set(x, doc);
    } else {
        mpz_powm(x, info->vk_u, pk->e, pk->n);
        mpz_mul(x, x, doc);
        mpz_mod(x, x, pk->n);
    }


    // v

    // x~ = x^4 % n
    mpz_powm_ui(xtilde, x, 4, pk->n);

    // xi_2 = xi^2 % n
    mpz_powm_ui(xi2, xi, 2, pk->n);


    // v' = v^z * v_i^(-c)
    mpz_powm(v_prime, info->vk_i[id], signature->c, pk->n);
    mpz_invert(v_prime, v_prime, pk->n);

    mpz_powm(aux, info->vk_v, signature->z, pk->n);
    mpz_mul(v_prime, v_prime, aux);
    mpz_mod(v_prime, v_prime, pk->n);

    // x' = x~^z * x_i^(-2c)
    mpz_powm_ui(x_prime, xi, 2, pk->n);
    mpz_powm(x_prime, x_prime, signature->c, pk->n);
    mpz_invert(x_prime, x_prime, pk->n);

    mpz_powm(aux, xtilde, signature->z, pk->n);
    mpz_mul(x_prime, x_prime, aux);
    mpz_mod(x_prime, x_prime, pk->n);

#if 0
    gmp_printf("v=%Zd\nx_tilde=%Zd\nvi=%Zd\nxi_2=%Zd\nv_prime=%Zd\nx_prime=%Zd\n\n", info->vk_v, xtilde, info->vk_i[id], xi2, v_prime, x_prime);
#endif
    size_t v_len, xtilde_len, v_i_len, xi2_len, v_prime_len, x_prime_len;

    void * v_bytes = mpz_export(NULL, &v_len, 1, 1, 1, 0, info->vk_v);
    void * xtilde_bytes = mpz_export(NULL, &xtilde_len, 1, 1, 1, 0, xtilde);
    void * v_i_bytes = mpz_export(NULL, &v_i_len, 1, 1, 1, 0, info->vk_i[id]);
    void * xi2_bytes = mpz_export(NULL, &xi2_len, 1, 1, 1, 0, xi2);
    void * v_prime_bytes = mpz_export(NULL, &v_prime_len, 1, 1, 1, 0, v_prime);
    void * x_prime_bytes = mpz_export(NULL, &x_prime_len, 1, 1, 1, 0, x_prime);

    // Initialization of the digest context

    unsigned char hash[HASH_LEN];
    MHASH sha = mhash_init(MHASH_SHA256);

    mhash(sha, v_bytes, v_len);
    mhash(sha, xtilde_bytes, xtilde_len);
    mhash(sha, v_i_bytes, v_i_len);
    mhash(sha, xi2_bytes, xi2_len);
    mhash(sha, v_prime_bytes, v_prime_len);
    mhash(sha, x_prime_bytes, x_prime_len);

    mhash_deinit(sha, hash);

    void (*freefunc) (void *, size_t);
    mp_get_memory_functions (NULL, NULL, &freefunc);

    freefunc(v_bytes, v_len);
    freefunc(xtilde_bytes, xtilde_len);
    freefunc(v_i_bytes, v_i_len);
    freefunc(xi2_bytes, xi2_len);
    freefunc(v_prime_bytes, v_prime_len);
    freefunc(x_prime_bytes, x_prime_len);

    mpz_t h;
    mpz_init(h);
    mpz_import(h, HASH_LEN, 1, 1, 1, 0, hash);
    mpz_mod(h, h, pk->n);

    int result = mpz_cmp(h, signature->c);

    mpz_clears(x, xtilde, xi2, v_prime, x_prime, h, NULL);

    return result == 0;
}

/* All the signatures are valid before getting them here. 
 * k is the number of signatures in the array
 * TODO: verify if the array has less than info->l signatures.
 */
void join_signatures(mpz_t out, mpz_t document, 
        const signature_share_t ** signatures, int k, 
        const public_key_t * pk, const key_meta_info_t * info){

    mpz_t e_prime, w, lambda_k_2, delta, aux, a, b, wa, xb, x;
    mpz_inits(e_prime, w, lambda_k_2, delta, aux, a, b, wa, xb, x, NULL);

    mpz_mod(x, document, pk->n);

    mpz_set_si(e_prime, 4);

    /* Calculate w */
    mpz_set_si(w, 1);
    mpz_fac_ui(delta, info->l);

    for(int i = 0; i<k; i++) {
        int id = signatures[i]->id;
        lagrange_interpolation(lambda_k_2, 0, id, k, signatures, delta);
        mpz_mul_si(lambda_k_2, lambda_k_2, 2);
        mpz_powm(aux, signatures[i]->signature, lambda_k_2, pk->n);
        mpz_mul(w, w, aux);
        mpz_mod(w, w, pk->n);
    }

    mpz_gcdext(aux, a, b, pk->e, e_prime);

    mpz_powm(wa, w, a, pk->n);
    mpz_mod(x, document, pk->n);
    mpz_powm(xb, x, b, pk->n);

    mpz_mul(out, wa, xb);
    if (mpz_jacobi(document, pk->n) == -1) {
        mpz_fdiv_q(out, out, info->vk_u);
    }
    mpz_mod(out, out, pk->n);

    mpz_clears(e_prime, w, lambda_k_2, delta, aux, a, b, wa, xb, x, NULL);
}

key_share_t * generate_key_shares(const key_meta_info_t * info, mpz_t n, mpz_t d, mpz_t m){ 
    // static const long L1 = 128L; // Security parameter.

    int i, exists_inv;
    mpz_t rand, delta, delta_inv;
    mpz_inits(rand, delta, delta_inv, NULL);

    mpz_fac_ui(delta, info->l);
    exists_inv = mpz_invert(delta_inv, delta, m);

    key_share_t * shares = malloc(sizeof(*shares)*info->l);

    poly_t * poly = create_random_poly(d, info->k - 1, m);

    for(i=0; i<info->l; i++) {
        // shares[0] => s_1...
        mpz_inits(shares[i].s_i, shares[i].n, NULL);
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

    return shares;
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

/* Should be used after group verifier generation */
void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares) {
    info->vk_i = malloc(info->l * sizeof(*(info->vk_i)));
    for (int i=0; i<info->l; i++) {
        mpz_init(info->vk_i[i]);
        mpz_powm(info->vk_i[i], info->vk_v, shares[i].s_i, shares[i].n);
    }
} 

void lagrange_interpolation(mpz_t out, int i, int j, int k, const signature_share_t ** S, mpz_t delta) {
    int j_; // j' from the paper.
    mpz_set(out, delta);

    for (int n=0; n<k; n++) {
        j_ = S[n]->id + 1;
        if(j_ != j) {
            mpz_mul_si(out, out, i - j_);
        }
    }

    for (int n=0; n<k; n++) {
        j_ = S[n]->id + 1;
        if(j_ != j) {
            mpz_fdiv_q_ui(out, out, j - j_);
        }
    }

}
