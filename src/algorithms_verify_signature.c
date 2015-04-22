#include "algorithms.h"

#include "mhash.h"


tc_error_t verify_signature(const signature_share_t * signature, int id, mpz_t doc,
        const public_key_t * pk, const key_meta_info_t * info){
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
    mpz_import(h, HASH_LEN, 1, 1, 0, 0, hash);
    mpz_mod(h, h, pk->n);

    int result = mpz_cmp(h, signature->c);

    mpz_clears(x, xtilde, xi2, v_prime, x_prime, h, NULL);

    return result == 0;
}
