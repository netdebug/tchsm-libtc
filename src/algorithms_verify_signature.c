#include <gmp.h>
#include <mhash.h>

#include "tc.h"
#include "tc_internal.h"

extern const unsigned int HASH_LEN; /* Defined somewhere :P */

int tc_verify_signature(const signature_share_t * signature, const bytes_t * doc, const key_metainfo_t * info){
    mpz_t x, xi, z, c, n, e, v, u, vk_i, delta, xtilde, xi2, neg_c, v_prime, xi_neg_2c, x_prime, aux;
    mpz_inits(x, xi, z, c, n, e, v, u, vk_i, delta, xtilde, xi2, neg_c, v_prime, xi_neg_2c, x_prime, aux, NULL);
    
    TC_BYTES_TO_MPZ(x, doc);
    TC_BYTES_TO_MPZ(xi, signature->x_i);
    TC_BYTES_TO_MPZ(z, signature->z);
    TC_BYTES_TO_MPZ(c, signature->c);
    TC_BYTES_TO_MPZ(n, info->public_key->n);
    TC_BYTES_TO_MPZ(e, info->public_key->e);
    TC_BYTES_TO_MPZ(v, info->vk_v);
    TC_BYTES_TO_MPZ(u, info->vk_u);

    int idx = TC_ID_TO_INDEX(signature->id);
    TC_BYTES_TO_MPZ(vk_i, info->vk_i + idx);

    if(mpz_jacobi(x, n) == -1) {
	mpz_t ue;
	mpz_init(ue);
	mpz_powm(ue, u, e, n);
	mpz_mul(x, x, ue);
	mpz_mod(x, x, n);
	mpz_clear(ue);
    }

    // v

    // u

    // x~ = x^4 % n
    mpz_powm_ui(xtilde, x, 4ul, n);

    // v_i

    // xi_2 = xi^2 % n
    mpz_powm_ui(xi2, xi, 2, n);


    // v' = v^z * v_i^(-c)
    mpz_neg(neg_c, c);
    mpz_powm(v_prime, vk_i, neg_c, n);

    mpz_powm(aux, v, z, n);
    mpz_mul(v_prime, v_prime, aux);
    mpz_mod(v_prime, v_prime, n);

    // x' = x~^z * x_i^(-2c)
    
    mpz_mul_si(aux, neg_c, 2);
    mpz_powm(xi_neg_2c, xi, aux, n);

    mpz_powm(aux, xtilde, z, n);
    mpz_mul(x_prime, aux, xi_neg_2c);
    mpz_mod(x_prime, x_prime, n);

    size_t v_len, u_len, xtilde_len, v_i_len, xi2_len, v_prime_len, x_prime_len;

    void * v_bytes = TC_TO_OCTETS(&v_len, v);
    void * u_bytes = TC_TO_OCTETS(&u_len, u);
    void * xtilde_bytes = TC_TO_OCTETS(&xtilde_len, xtilde);
    void * v_i_bytes = TC_TO_OCTETS(&v_i_len, vk_i);
    void * xi2_bytes = TC_TO_OCTETS(&xi2_len, xi2);
    void * v_prime_bytes = TC_TO_OCTETS(&v_prime_len, v_prime);
    void * x_prime_bytes = TC_TO_OCTETS(&x_prime_len, x_prime);

    // Initialization of the digest context

    unsigned char hash[HASH_LEN];
    MHASH sha = mhash_init(MHASH_SHA256);

    mhash(sha, v_bytes, v_len);
    mhash(sha, u_bytes, u_len);
    mhash(sha, xtilde_bytes, xtilde_len);
    mhash(sha, v_i_bytes, v_i_len);
    mhash(sha, xi2_bytes, xi2_len);
    mhash(sha, v_prime_bytes, v_prime_len);
    mhash(sha, x_prime_bytes, x_prime_len);

    mhash_deinit(sha, hash);

    void (*freefunc) (void *, size_t);
    mp_get_memory_functions (NULL, NULL, &freefunc);

    freefunc(v_bytes, v_len);
    freefunc(u_bytes, u_len);
    freefunc(xtilde_bytes, xtilde_len);
    freefunc(v_i_bytes, v_i_len);
    freefunc(xi2_bytes, xi2_len);
    freefunc(v_prime_bytes, v_prime_len);
    freefunc(x_prime_bytes, x_prime_len);

    mpz_t h;
    mpz_init(h);
    TC_GET_OCTETS(h, HASH_LEN, hash);
    mpz_mod(h, h, n);
    int result = mpz_cmp(h, c);
    mpz_clear(h);

    mpz_clears(x, xi, z, c, n, e, v, u, vk_i, delta, xtilde, xi2, neg_c, v_prime, xi_neg_2c, x_prime, aux, NULL);

    return result == 0;
}
