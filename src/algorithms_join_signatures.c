#include <stdio.h>
#include <assert.h>
#include <gmp.h>
#include <stdlib.h>

#include "tc.h"
#include "tc_internal.h"

void lagrange_interpolation(mpz_t out, int j, int k,
			    const signature_share_t ** S, const mpz_t delta);

/* All the signatures are valid before getting them here.
 * k is the number of signatures in the array
 * TODO: verify if the array has less than info->l signatures.
 */

/**
 * @param out the result of the algorithm.
 * @param document the document that has been signed.
 * @param signatures the array of pointers to si shares, that are received.
 * @param k the number of si shares received.
 * @param pk a pointer to the public key of this process
 * @param info a pointer to the meta info of the key set
 */
bytes_t * tc_join_signatures(const signature_share_t ** signatures,
			     const bytes_t * document, const key_metainfo_t * info) {
    assert(signatures != NULL);
#ifndef NDEBUG
    for (int i = 0; i < info->k; i++) {
	assert(signatures[i] != NULL);
    }
#endif
    assert(document != NULL && document->data != NULL);
    assert(info != NULL);

    bytes_t * out = tc_init_bytes(NULL, 0);

    mpz_t x, n, e, u, delta, e_prime, w, s_i, lambda_k_2, aux, a, b, wa, xb, y;
#if (__GNU_MP_VERSION >= 5)
    mpz_inits(x, n, e, u, delta, e_prime, w, s_i, lambda_k_2, aux, a, b, wa, xb, y,
	      NULL);
#else
    mpz_init(x);
    mpz_init(n);
    mpz_init(e);
    mpz_init(u);
    mpz_init(delta);
    mpz_init(e_prime);
    mpz_init(w);
    mpz_init(s_i);
    mpz_init(lambda_k_2);
    mpz_init(aux);
    mpz_init(a);
    mpz_init(b);
    mpz_init(wa);
    mpz_init(xb);
    mpz_init(y);
#endif

    TC_BYTES_TO_MPZ(x, document);
    TC_BYTES_TO_MPZ(n, info->public_key->n);
    TC_BYTES_TO_MPZ(e, info->public_key->e);
    TC_BYTES_TO_MPZ(u, info->vk_u);

    // x = doc if (doc | n) == 1 else doc * u^e
    int jacobied = 0;
    if(mpz_jacobi(x, n) == -1) {
	mpz_t ue;
	mpz_init(ue);
	mpz_powm(ue, u, e, n);
	mpz_mul(x, x, ue);
	mpz_mod(x, x, n);
	mpz_clear(ue);
	jacobied = 1;
    }

    mpz_fac_ui(delta, info->l);
    mpz_set_ui(e_prime, 4);

    /* Calculate w */
    mpz_set_si(w, 1);

    int k = info->k;
    for (int i = 0; i < k; i++) {
	int id = signatures[i]->id;
	TC_BYTES_TO_MPZ(s_i, signatures[i]->x_i);
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

    if (jacobied) {
	mpz_t inv_u;
	mpz_init(inv_u);
	mpz_invert(inv_u, u, n);
	mpz_mul(y, y, inv_u);
	mpz_clear(inv_u);
    }

    mpz_mod(y, y, n);

    TC_MPZ_TO_BYTES(out, y);

#if (__GNU_MP_VERSION >= 5)
    mpz_clears(x, n, e, u, delta, e_prime, w, s_i, lambda_k_2, aux, a, b, wa, xb,
	       y, NULL);
#else
    mpz_clear(x);
    mpz_clear(n);
    mpz_clear(e);
    mpz_clear(u);
    mpz_clear(delta);
    mpz_clear(e_prime);
    mpz_clear(w);
    mpz_clear(s_i);
    mpz_clear(lambda_k_2);
    mpz_clear(aux);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(wa);
    mpz_clear(xb);
    mpz_clear(y);
#endif

    assert(out != NULL && out->data != NULL);
    return out;
}

void lagrange_interpolation(mpz_t out, int j, int k,
			    const signature_share_t ** S, const mpz_t delta) {
    mpz_set(out, delta);
    mpz_t num, den;
    mpz_init_set_si(num, 1);
    mpz_init_set_si(den, 1);

    for (int i = 0; i < k; i++) {
	int id = S[i]->id;
	if (id != j) {
	    mpz_mul_si(num, num, id); // num <-- num*j_
	    mpz_mul_si(den, den, id - j); // den <-- den*(j_-j)
	}
    }

    mpz_mul(out, out, num);
    mpz_fdiv_q(out, out, den);

    mpz_clear(num);
    mpz_clear(den);
}

