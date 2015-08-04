#include "tc_internal.h"
#include <assert.h>
#include <stdlib.h>

void lagrange_interpolation(mpz_t out, int j, int k, const signature_share_t ** S, const mpz_t delta);

/* All the signatures are valid before getting them here.
* k is the number of signatures in the array
* TODO: verify if the array has less than info->l signatures.
*/

/**
* @param out the result of the algorithm.
* @param document the document that has been signed.
* @param signatures the array of pointers to signature shares, that are received.
* @param k the number of signature shares received.
* @param pk a pointer to the public key of this process
* @param info a pointer to the meta info of the key set
*/
bytes_t * tc_join_signatures(const signature_share_t ** signatures, const bytes_t * document, const key_meta_info_t * info) {
    bytes_t * out = tc_init_bytes(NULL, 0);

    mpz_t x, n, e, delta, e_prime, w, s_i, lambda_k_2, aux, a, b, wa, xb, y;
    mpz_inits(x, n, e, delta, e_prime, w, s_i, lambda_k_2, aux, a, b, wa, xb, y, NULL);

    TC_BYTES_TO_MPZ(x, document);
    TC_BYTES_TO_MPZ(n, info->public_key->n);
    TC_BYTES_TO_MPZ(e, info->public_key->e);

    mpz_mod(x, x, n);
    mpz_fac_ui(delta, info->l);

    mpz_mul(e_prime, delta, delta);
    mpz_mul_ui(e_prime, e_prime, 4);

    /* Calculate w */
    mpz_set_si(w, 1);

    int k = info->k;
    for(int i = 0; i<k; i++) {
        int id = signatures[i]->id;
        TC_BYTES_TO_MPZ(s_i, signatures[i]->signature);
        lagrange_interpolation(lambda_k_2, id, k, signatures, delta);
        mpz_mul_ui(lambda_k_2, lambda_k_2, 2);

        mpz_powm(aux, s_i, lambda_k_2, n);
        mpz_mul(w, w, aux);
    }
    mpz_mod(w, w, n);

    mpz_gcdext(aux, a, b, e_prime, e);

    mpz_powm(wa, w, a, n);
    mpz_powm(xb, x, b, n);

    mpz_mul(y, wa, xb);
    mpz_mod(y, y, n);

    TC_MPZ_TO_BYTES(out, y);

    mpz_clears(x, n, e, delta, e_prime, w, s_i, lambda_k_2, aux, a, b, wa, xb, y, NULL);
    return out;
}

void lagrange_interpolation(mpz_t out, int j, int k, const signature_share_t ** S, const mpz_t delta) {
    mpz_set(out, delta);
    mpz_t num, den;
    mpz_init_set_si(num, 1);
    mpz_init_set_si(den, 1);

    for(int i=0; i<k; i++) { 
        int id = S[i]->id;
        if (id != j) {
            mpz_mul_si(num, num, id); // num <-- num*j_
            mpz_mul_si(den, den, id - j); // den <-- den*(j_-j)
        }
    }

    mpz_mul(out, out, num);
    mpz_fdiv_q(out, out, den); 

    mpz_clears(num, den, NULL);
}
