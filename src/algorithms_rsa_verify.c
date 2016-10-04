/*
 * algorithms_rsa_verify.c
 *
 *  Created on: 28-07-2015
 *      Author: franchoco
 */

#include <gmp.h>
#include <stdlib.h>

#include "tc.h"
#include "tc_internal.h"

int tc_rsa_verify(bytes_t * signature, bytes_t * doc, key_metainfo_t * info, tc_hash_type_t hashtype) {

	bytes_t * doc_pkcs1 = tc_prepare_document(doc, hashtype, info);

	mpz_t c, x, e, n, new_x;
#if (__GNU_MP_VERSION >= 5)
	mpz_inits(c, x, e, n, new_x, NULL);
#else
    mpz_init(c);
    mpz_init(x);
    mpz_init(e);
    mpz_init(n);
    mpz_init(new_x);
#endif

	TC_BYTES_TO_MPZ(x, doc_pkcs1);
	TC_BYTES_TO_MPZ(c, signature);
	TC_BYTES_TO_MPZ(e, info->public_key->e);
	TC_BYTES_TO_MPZ(n, info->public_key->n);

	mpz_powm(new_x, c, e, n);
	int cmp = mpz_cmp(x, new_x);

	tc_clear_bytes(doc_pkcs1);
#if (__GNU_MP_VERSION >= 5)
	mpz_clears(c, x, e, n, new_x, NULL);
#else
    mpz_clear(c);
    mpz_clear(x);
    mpz_clear(e);
    mpz_clear(n);
    mpz_clear(new_x);
#endif

	return cmp == 0;
}
