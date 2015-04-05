#include "algorithms.h"

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
void join_signatures(mpz_t out, const signature_share_t * signatures, int k, mpz_t document, const public_key_t * pk, const key_meta_info_t * info) {

  mpz_t e_prime, w, lambda_k_2, delta, aux, a, b, wa, xb, x;
  mpz_inits(e_prime, w, lambda_k_2, delta, aux, a, b, wa, xb, x, NULL);

  mpz_mod(x, document, pk->n);

  mpz_set_si(e_prime, 4);

  /* Calculate w */
  mpz_set_si(w, 1);
  mpz_fac_ui(delta, info->l);

  for(int i = 0; i<k; i++) {
    int id = signatures[i].id;
    lagrange_interpolation(lambda_k_2, 0, id, k, signatures, delta);
    mpz_mul_si(lambda_k_2, lambda_k_2, 2);
    mpz_powm(aux, signatures[i].signature, lambda_k_2, pk->n);
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

void lagrange_interpolation(mpz_t out, int i, int j, int k, const signature_share_t * S, mpz_t delta) {
  int j_; // j' from the paper.
  mpz_set(out, delta);

  for (int n=0; n<k; n++) {
    j_ = S[n].id + 1; // id \in [1..l], S[..]->id \in [0..l-1]
    if(j_ != j) {
      mpz_mul_si(out, out, i - j_);
    }
  }

  for (int n=0; n<k; n++) {
    j_ = S[n].id + 1;
    if(j_ != j) {
      mpz_fdiv_q_ui(out, out, j - j_);
    }
  }

}
