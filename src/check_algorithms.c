#include <stdlib.h>
#include <check.h>
#include <gmp.h>
#include "algorithms.h"
#include "mathutils.h"
#include "tcb.h"
#include <mhash.h>

int verify_rsa(const mpz_t signature, const mpz_t hash, const public_key_t * pk) {
    mpz_t dec;
    mpz_init(dec);
    mpz_powm(dec, signature, pk->e, pk->n);

    int res = mpz_cmp(dec, hash);

    mpz_clear(dec);
    return res;
}

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

START_TEST(test_generate_keys) {
    mpz_t d, aux, delta;
    mpz_inits(d, aux, delta, NULL);
    key_meta_info_t info;
    public_key_t pk;
    init_public_key(&pk);
    init_key_meta_info(&info, 512, 2, 3);

    key_share_t shares[info.l];
    init_key_shares(shares, &info);

    generate_keys(shares, &info, &pk);

    mpz_fac_ui(delta, info.l);

    mpz_mul(aux, delta, shares[0].s_i);
    mpz_mul_ui(d, aux, 2);
    mpz_mul(aux, delta, shares[1].s_i);
    mpz_sub(d, d, aux);

    mpz_mul(aux, d, pk.e);
    mpz_mod(aux, aux, pk.m);

    ck_assert(mpz_cmp_ui(aux, 1) == 0);

    mpz_clears(d, aux, delta, NULL);

    clear_key_shares(shares, &info);
    clear_key_meta_info(&info);
    clear_public_key(&pk);
}
END_TEST

START_TEST(test_verify){
    key_meta_info_t info;
    public_key_t public_key;

    init_key_meta_info(&info, 512, 2, 3);
    init_public_key(&public_key);

    key_share_t shares[info.l];
    init_key_shares(shares, &info);
    generate_keys(shares, &info, &public_key);

    mpz_t doc, signature;
    mpz_init(signature);
    mpz_init_set_str(doc, "95951009936565630770613232106413300773619435751148631183701517132539356488156", 10);

    signature_share_t signatures[info.l];
    for(int i=0; i<info.l; i++) {
        init_signature_share(signatures + i);
    }

    for (int i=0; i<info.l; i++) {
        node_sign(signatures + i, shares + i, i, doc, &public_key, &info);
        int verify = verify_signature(signatures + i, i, doc, &public_key, &info);
        ck_assert(verify);
    }

    for(int i=0; i<info.l; i++) {
        clear_signature_share(signatures + i);
    }

    mpz_clears(doc, signature, NULL);

    clear_key_shares(shares, &info);
    clear_public_key(&public_key);
    clear_key_meta_info(&info);
}
END_TEST

START_TEST(test_complete_sign){
    key_meta_info_t info;
    public_key_t public_key;
    init_key_meta_info(&info, 512, 2, 3);
    init_public_key(&public_key);

    key_share_t shares[info.l];
    init_key_shares(shares, &info);
    generate_keys(shares, &info, &public_key);

    mpz_t doc;
    mpz_t signature;
    mpz_init(signature);
    mpz_init(doc);

    unsigned char document[] = "Hola mundo";
    unsigned char hash[32];
    MHASH sha = mhash_init(MHASH_SHA256);
    mhash(sha, document, 10);
    mhash_deinit(sha, hash);

    mpz_import(doc, 32, 1, 1, 0, 0, hash);

    signature_share_t signatures[info.l];
    for(int i=0; i<info.l; i++) {
        init_signature_share(signatures + i);
    }

    for (int i=0; i<info.l; i++) {
        node_sign(signatures + i, &(shares[i]), i, doc, &public_key, &info);
        int verify = verify_signature(signatures + i, i, doc, &public_key, &info);
        ck_assert(verify);
    }

    join_signatures(signature,(const signature_share_t *)(signatures), info.l, doc, &public_key, &info);

    ck_assert(verify_rsa(signature, doc, &public_key));

    for(int i=0; i<info.l; i++) {
        clear_signature_share(signatures + i);
    }
    clear_key_shares(shares, &info);
    mpz_clears(doc, signature, NULL);
    clear_public_key(&public_key);
    clear_key_meta_info(&info);


}
END_TEST

START_TEST(test_lagrange_interpolation){
    signature_share_t S[3];
    S[0].id = 0;
    S[1].id = 3;
    S[2].id = 4;

    mpz_t delta;
    mpz_init_set_ui(delta, 120);
    mpz_t out;
    mpz_init(out);

    lagrange_interpolation(out, 0, 0, 3, S, delta);
    ck_assert(mpz_cmp_si(out, -1) == 0);
    lagrange_interpolation(out, 0, 1, 3, S, delta);
    ck_assert(mpz_cmp_si(out, 0) == 0);
    lagrange_interpolation(out, 0, 2, 3, S, delta);
    ck_assert(mpz_cmp_si(out, -1) == 0);

    mpz_clears(delta, out, NULL);
}
END_TEST

// TODO!
#if 0
START_TEST(test_generate_key_shares){

}
END_TEST

START_TEST(test_generate_group_verifier){

}

START_TEST(test_generate_group_verifier){

}
END_TEST

START_TEST(test_random_dev){

}
END_TEST

START_TEST(test_random_prime){
    /* Testear que sea primo XD */
}
END_TEST
#endif
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

    tcase_add_test(tc_core, test_generate_keys);
    tcase_add_test(tc_core, test_generate_safe_prime);
    //    tcase_add_test(tc_core, test_node_sign);
    tcase_add_test(tc_core, test_verify);
    tcase_add_test(tc_core, test_complete_sign);
    tcase_add_test(tc_core, test_poly_eval);
    tcase_add_test(tc_core, test_poly_eval_ui);
    tcase_add_test(tc_core, test_lagrange_interpolation);
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
