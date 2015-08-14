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

int tc_rsa_verify(bytes_t * signature, bytes_t * doc, key_meta_info_t * info, tc_hash_type_t hashtype) {

	bytes_t * doc_pkcs1 = tc_prepare_document(doc, hashtype, info);

	mpz_t c, x, e, n, new_x;
	mpz_inits(c, x, e, n, new_x, NULL);
	TC_BYTES_TO_MPZ(c, signature);
	TC_BYTES_TO_MPZ(x, doc_pkcs1);
	TC_BYTES_TO_MPZ(e, info->public_key->e);
	TC_BYTES_TO_MPZ(n, info->public_key->n);

	mpz_powm(new_x, c, e, n);

	int cmp = mpz_cmp(x, new_x);

	tc_clear_bytes(doc_pkcs1);
	mpz_clears(c, x, e, n, new_x, NULL);

	return cmp == 0;
}
