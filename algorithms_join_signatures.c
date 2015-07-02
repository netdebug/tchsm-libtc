#include "tc.h"

#include <assert.h>

void lagrange_interpolation(mpz_t out, int i, int k, const signature_share_t * const * S, const mpz_t delta);

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
tc_error_t tc_join_signatures(mpz_t out, const signature_share_t * const * signatures, int k, mpz_t document, const key_meta_info_t * info) {

  mpz_t e_prime, w, lambda_k_2, delta, aux, a, b, wa, xb, x, t1;
  mpz_inits(e_prime, w, lambda_k_2, delta, aux, a, b, wa, xb, x, t1, NULL);

  mpz_mod(x, document, info->public_key->n);
  mpz_fac_ui(delta, info->l);

  mpz_mul(t1, delta, delta);
  mpz_mul_ui(e_prime, t1, 4);

  /* Calculate w */
  mpz_set_si(w, 1);

  for(int i = 0; i<k; i++) {
    int id = signatures[i]->id;
    lagrange_interpolation(t1, id, k, signatures, delta);
    mpz_mul_ui(lambda_k_2, t1, 2);
    mpz_powm(t1, signatures[i]->signature, lambda_k_2, info->public_key->n);
    mpz_mul(w, w, t1);
  }
  mpz_mod(w, w, info->public_key->n);

  mpz_gcdext(aux, a, b, e_prime, info->public_key->e);

  mpz_powm(wa, w, a, info->public_key->n);
  mpz_powm(xb, x, b, info->public_key->n);

  mpz_mul(out, wa, xb);
  mpz_mod(out, out, info->public_key->n);

  mpz_clears(e_prime, w, lambda_k_2, delta, aux, a, b, wa, xb, x, t1, NULL);

  return 0;
}

void lagrange_interpolation(mpz_t out, int j, int k, const signature_share_t * const * S, const mpz_t delta) {
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
