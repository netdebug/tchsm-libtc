#include "algorithms.h"
#include <mhash.h>

/*
  Signs the document with the nodes share.
  It is supposed that all integers are initialized. Even the ones in signatureshare_t out.
 */

/**
  * @param out the resulting of the procedure
  * @param share the key share that has to be used in this procedure
  * @param pk the public key corresponding to the key share
  * @param info the meta info of the key share set
  * @param doc the document to be signed
  */
tc_error_t node_sign(signature_share_t * out, const key_share_t * share, mpz_t doc, 
        const public_key_t * pk, const key_meta_info_t * info){

    /* ti are temporary variables */
    mpz_t x, r, t1, t2, xi, xi_2, v_prime, x_tilde, x_prime, n, delta;
    mpz_inits(x, r, t1, t2, xi, xi_2, v_prime, x_tilde, x_prime, n, delta, NULL);
    mpz_set(n, pk->n);
    mpz_fac_ui(delta, info->l);

    const unsigned long n_bits = mpz_sizeinbase(n, 2); // Bit size of the key.

    mpz_mod(x, doc, n);
   
    // xi = x^(2*delta*share)
    mpz_mul_ui(t1, share->s_i, 2);
    mpz_mul(t2, t1, delta);
    mpz_powm(xi, x, t2, n);

    // xi_2 = xi^2 
    mpz_powm_ui(xi_2, xi, 2, n);

    // r = abs(random(bytes_len))
    random_dev(r, n_bits + 2*HASH_LEN*8);

    // v_prime = v^r % n
    mpz_powm(v_prime, info->vk_v, r, n);

    // x_tilde = x^4 % n
    mpz_mul_ui(t1, delta, 4);
    mpz_powm(x_tilde, x, t1, n);

    // x_prime = x_tilde^r % n
    mpz_powm(x_prime, x_tilde, r, n);

   // Every number calculated, now to bytes...
    size_t v_len, x_tilde_len, v_i_len, xi_2_len, v_prime_len, x_prime_len;


    void * v_bytes = TC_TO_OCTETS(&v_len, info->vk_v);
    void * x_tilde_bytes = TC_TO_OCTETS(&x_tilde_len, x_tilde);
    void * v_i_bytes = TC_TO_OCTETS(&v_i_len, info->vk_i[TC_ID_TO_INDEX(share->id)]);
    void * xi_2_bytes = TC_TO_OCTETS(&xi_2_len, xi_2);
    void * v_prime_bytes = TC_TO_OCTETS(&v_prime_len, v_prime);
    void * x_prime_bytes = TC_TO_OCTETS(&x_prime_len, x_prime);

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

    TC_GET_OCTETS(t1, HASH_LEN, hash);
    mpz_mod(out->c, t1, n);
    free(hash);

    mpz_mul(t1, out->c, share->s_i);
    mpz_add(out->z, t1, r);

    mpz_set(out->signature, xi);
    out->id = share->id;

    mpz_clears(x, r, t1, t2, xi, xi_2, v_prime, x_tilde, x_prime, n, delta, NULL);
    return 0;
}
