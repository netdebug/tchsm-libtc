#include <gmp.h>
#include <mhash.h>
#include "mathutils.h"
#include "tc.h"
#include "tc_internal.h"

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


const unsigned int HASH_LEN = 32; // sha256 => 256 bits => 32 bytes

signature_share_t * tc_node_sign(const key_share_t * share, const bytes_t * doc, const key_metainfo_t * info){
    signature_share_t * out = tc_init_signature_share();

    /* ti are temporary variables */
    mpz_t x, n, e, s_i, v, u, vk_i, xi, xi_2, r, v_prime, x_tilde, x_prime, c, z;
    mpz_inits(x, n, e, s_i, v, u, vk_i, xi, xi_2, r, v_prime, x_tilde, x_prime, c, z, NULL);

    TC_BYTES_TO_MPZ(x, doc);
    TC_BYTES_TO_MPZ(n, info->public_key->n);
    TC_BYTES_TO_MPZ(e, info->public_key->e);
    TC_BYTES_TO_MPZ(s_i, share->s_i);
    TC_BYTES_TO_MPZ(v, info->vk_v);
    TC_BYTES_TO_MPZ(u, info->vk_u);
    TC_BYTES_TO_MPZ(vk_i, info->vk_i + TC_ID_TO_INDEX(share->id));

    const unsigned long n_bits = mpz_sizeinbase(n, 2); // Bit size of the key.

    // x = doc if (doc | n) == 1 else doc * u^e
    if(mpz_jacobi(x, n) == -1) {
	mpz_t ue;
	mpz_init(ue);
	mpz_powm(ue, u, e, n);
	mpz_mul(x, x, ue);
	mpz_mod(x, x, n);
	mpz_clear(ue);
    }
    
    // xi = x^(2*share) mod n
    mpz_mul_ui(xi, s_i, 2);
    mpz_powm(xi, x, xi, n);

    // xi_2 = xi^2 
    mpz_powm_ui(xi_2, xi, 2, n);

    // r = abs(random(bytes_len))
    random_dev(r, n_bits + 2*HASH_LEN*8);

    // v_prime = v^r % n
    mpz_powm(v_prime, v, r, n);

    // x_tilde = x^4 % n
    mpz_powm_ui(x_tilde, x, 4ul, n);

    // x_prime = x_tilde^r % n
    mpz_powm(x_prime, x_tilde, r, n);

   // Every number calculated, now to bytes...
    size_t v_len, u_len, x_tilde_len, v_i_len, xi_2_len, v_prime_len, x_prime_len;


    void * v_bytes = TC_TO_OCTETS(&v_len, v);
    void * u_bytes = TC_TO_OCTETS(&u_len, u);
    void * x_tilde_bytes = TC_TO_OCTETS(&x_tilde_len, x_tilde);
    void * v_i_bytes = TC_TO_OCTETS(&v_i_len, vk_i);
    void * xi_2_bytes = TC_TO_OCTETS(&xi_2_len, xi_2);
    void * v_prime_bytes = TC_TO_OCTETS(&v_prime_len, v_prime);
    void * x_prime_bytes = TC_TO_OCTETS(&x_prime_len, x_prime);

    // Initialization of the digest context

    unsigned char * hash = alloc(HASH_LEN);
    MHASH sha = mhash_init(MHASH_SHA256);

    mhash(sha, v_bytes, v_len);
    mhash(sha, u_bytes, u_len);
    mhash(sha, x_tilde_bytes, x_tilde_len);
    mhash(sha, v_i_bytes, v_i_len);
    mhash(sha, xi_2_bytes, xi_2_len);
    mhash(sha, v_prime_bytes, v_prime_len);
    mhash(sha, x_prime_bytes, x_prime_len);

    mhash_deinit(sha, hash);

    void (*freefunc) (void *, size_t);
    mp_get_memory_functions (NULL, NULL, &freefunc);

    freefunc(v_bytes, v_len);
    freefunc(u_bytes, u_len);
    freefunc(x_tilde_bytes, x_tilde_len);
    freefunc(v_i_bytes, v_i_len);
    freefunc(xi_2_bytes, xi_2_len);
    freefunc(v_prime_bytes, v_prime_len);
    freefunc(x_prime_bytes, x_prime_len);

    TC_GET_OCTETS(c, HASH_LEN, hash);
    mpz_mod(c, c, n);
    free(hash);

    mpz_mul(z, c, s_i);
    mpz_add(z, z, r);

    TC_MPZ_TO_BYTES(out->c, c);
    TC_MPZ_TO_BYTES(out->z, z);
    TC_MPZ_TO_BYTES(out->x_i, xi);
    out->id = share->id;

    mpz_clears(x, n, e, s_i, v, u, vk_i, xi, xi_2, r, v_prime, x_tilde, x_prime, c, z, NULL);
    return out;
}
