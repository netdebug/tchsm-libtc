#include "algorithms.h"
#include <mhash.h>

/*
  Signs the document with the nodes share.
  It is supposed that all integers are initialized. Even the ones in signatureshare_t out.
 */

/**
  * @param out the resulting of the procedure
  * @param node_id the corresponding id of this node
  * @param share the key share that has to be used in this procedure
  * @param pk the public key corresponding to the key share
  * @param info the meta info of the key share set
  * @param doc the document to be signed
  */
void node_sign(signature_share_t * out, const key_share_t * share, int node_id, mpz_t doc, const public_key_t * pk, const key_meta_info_t * info) {

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

    mpz_import(out->c, HASH_LEN, 1, 1, 0, 0, hash);
    mpz_mod(out->c, out->c, n);
    free(hash);

    mpz_mul(out->z, out->c, share->s_i);
    mpz_add(out->z, out->z, r);

    mpz_set(out->signature, xi);
    out->id = node_id;

    mpz_clears(x, r, xi, xi_2, v_prime, x_tilde, x_prime, n, NULL);
}
