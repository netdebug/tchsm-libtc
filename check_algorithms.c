/***
 * Unit and functional tests.
 *
 * Generally we only test correct cases.
 * TODO: We need to test failure cases.
 */
#include "tc.h"
#include "tc_internal.h"
#include "mathutils.h"

#include <gmp.h>
#include <mhash.h>

#include <check.h>
#include <nettle/rsa.h>

#include <stdlib.h>

void lagrange_interpolation(mpz_t out, int j, int k, const signature_share_t * const * S, mpz_t delta);
void generate_safe_prime(mpz_t out, int bit_len, random_fn random);

START_TEST(test_lagrange_interpolation){
    const int k = 5;
    mpz_t out, delta;
    mpz_inits(out, delta, NULL);

    signature_share_t SS[] = {
        {.id = 1},
        {.id = 2},
        {.id = 3},
        {.id = 4},
        {.id = 5}   
    };
    signature_share_t const* S[] = { SS, SS+1, SS+2, SS+3, SS+4 };

    mpz_fac_ui(delta, k);


    lagrange_interpolation(out, 1, k,  S, delta);
    ck_assert(mpz_cmp_si(out, 600) == 0);
    lagrange_interpolation(out, 2, k, S, delta);
    ck_assert(mpz_cmp_si(out, -1200) == 0);
    lagrange_interpolation(out, 3, k, S, delta);
    ck_assert(mpz_cmp_si(out, 1200) == 0);
    lagrange_interpolation(out, 4, k, S, delta);
    ck_assert(mpz_cmp_si(out, -600) == 0);
    lagrange_interpolation(out, 5, k, S, delta);
    ck_assert(mpz_cmp_si(out, 120) == 0);

    mpz_clears(out, delta, NULL);
}
END_TEST

START_TEST(test_generate_safe_prime) {
    mpz_t p, q;
    mpz_inits(p,q,NULL);
    generate_safe_prime(p, 512, random_dev);
    mpz_sub_ui(q, p, 1);
    mpz_fdiv_q_ui(q, q, 2);

    ck_assert(mpz_probab_prime_p(p, 25));
    ck_assert(mpz_probab_prime_p(q, 25));
    mpz_clears(p,q,NULL);
}
END_TEST

START_TEST(test_verify_invert) {
    mpz_t p, q, p_, q_, m, e, d, r;
    mpz_inits(p,q, p_, q_, m, e, d, r, NULL);
    generate_safe_prime(p, 512, random_dev);
    generate_safe_prime(q, 512, random_dev);

    mpz_sub_ui(p_, p, 1);
    mpz_fdiv_q_ui(p_, p_, 2);
    mpz_sub_ui(q_, q, 1);
    mpz_fdiv_q_ui(q_, q_, 2);

    mpz_mul(m, p_, q_);

    mpz_set_ui(e, 65537);

    mpz_invert(d, e, m);

    mpz_mul(r, d, e);
    mpz_mod(r, r, m);

    ck_assert(mpz_cmp_si(r, 1) == 0);

    mpz_clears(p,q, p_, q_, m, e, d, r, NULL);
}
END_TEST



START_TEST(test_complete_sign){
    key_meta_info_t info;
    tc_init_key_meta_info(&info, 1024, 3, 5);

    key_share_t shares[info.l];
    tc_init_key_shares(shares, &info);

    tc_generate_keys(shares, &info);

    bytes_t doc = { (void*) "Hola mundo", 10 };
    bytes_t doc_pkcs1;
    tc_prepare_document(&doc_pkcs1, &doc, TC_SHA256, &info);

    signature_share_t ss[info.l];
    signature_share_t * signatures[info.l];
    for(int i=0; i<info.l; i++) {
        signatures[i] = tc_init_signature_share( ss + i);
    }

    for (int i=0; i<info.l; i++) {
        tc_node_sign(signatures[i], shares + i, &doc_pkcs1, &info);
        int verify = tc_verify_signature(signatures[i], &doc_pkcs1, &info);
        ck_assert(verify);
    }

    bytes_t signature;
    tc_join_signatures(&signature, (void*)signatures, &doc_pkcs1, &info);

    struct rsa_public_key nettle_pk;
    nettle_rsa_public_key_init(&nettle_pk);
    
    TC_BYTES_TO_MPZ(nettle_pk.n, info.public_key->n);
    TC_BYTES_TO_MPZ(nettle_pk.e, info.public_key->e);

    mpz_t signature_z;
    mpz_init(signature_z);
    TC_BYTES_TO_MPZ(signature_z, signature);
    nettle_rsa_public_key_prepare(&nettle_pk);

    unsigned char hash[32];
    MHASH sha = mhash_init(MHASH_SHA256);
    mhash(sha, doc.data, doc.data_len);
    mhash_deinit(sha, hash);
    int result = nettle_rsa_sha256_verify_digest(&nettle_pk, hash, signature_z);

    mpz_clears(signature_z, NULL);
    free(signature.data);

    ck_assert(result);

    nettle_rsa_public_key_clear(&nettle_pk);
    for(int i=0; i<info.l; i++) {
        tc_clear_signature_share(signatures[i]);
    }
    tc_clear_key_shares(shares, &info);
    tc_clear_key_meta_info(&info);
}
END_TEST

START_TEST(test_poly_eval){
    // Easy cases.
    mpz_t coeffs[10];
    mpz_t x, res, y;
    mpz_inits(x, res, y, NULL);
    for(int i=0; i<10; i++){
        mpz_init_set_ui(coeffs[i], 1);
    }
    poly_t p = {.coeff = coeffs, .size=10};

    mpz_set_ui(x, 1);
    poly_eval(res, &p, x);
    ck_assert(mpz_cmp_ui(res, 10) == 0);

    mpz_set_ui(x, 10);

    mpz_set_str(y, "1111111111", 0);
    poly_eval(res, &p, x);
    ck_assert(mpz_cmp(res, y) == 0);

    mpz_set_ui(x, 0);
    poly_eval(res, &p, x);
    ck_assert(mpz_cmp_ui(res, 1) == 0);
}
END_TEST

START_TEST(test_poly_eval_ui){
    // Easy cases.
    mpz_t res,y;
    mpz_inits(res,y,NULL);

    mpz_t coeffs[10];
    for(int i=0; i<10; i++){
        mpz_init_set_ui(coeffs[i], 1);
    }

    poly_t p = {.coeff = coeffs, .size=10};

    poly_eval_ui(res, &p, 1);
    ck_assert(mpz_cmp_si(res, 10) == 0);

    mpz_set_str(y, "1111111111", 0);
    poly_eval_ui(res, &p, 10);
    ck_assert(mpz_cmp(res, y) == 0);

    poly_eval_ui(res, &p, 0);
    ck_assert(mpz_cmp_si(res, 1) == 0);
    mpz_clears(res,y,NULL);
}
END_TEST


Suite * algorithms_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Algorithms");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_lagrange_interpolation);
    tcase_add_test(tc_core, test_generate_safe_prime);
    tcase_add_test(tc_core, test_verify_invert);
    tcase_add_test(tc_core, test_poly_eval);
    tcase_add_test(tc_core, test_poly_eval_ui);
    tcase_add_test(tc_core, test_complete_sign);
    suite_add_tcase(s, tc_core);

    tcase_set_timeout(tc_core, 240);

    return s;
}

int main() {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = algorithms_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
