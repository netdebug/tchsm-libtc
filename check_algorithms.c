#include <stdlib.h>
#include <check.h>
#include <gmp.h>
#include "algorithms.h"
#include "mathutils.h"
#include "tcb.h"
#include <mhash.h>
#include <nettle/rsa.h>

void generate_safe_prime(mpz_t out, int bit_len, random_fn random);
void generate_key_shares(key_share_t * shares, const key_meta_info_t * info, mpz_t n, mpz_t d, mpz_t m);
void generate_group_verifier(key_meta_info_t * info, mpz_t n);
void generate_share_verifiers(key_meta_info_t * info, const key_share_t * shares);

void lagrange_interpolation(mpz_t out, int j, int k, const signature_share_t * S, mpz_t delta);

START_TEST(test_lagrange_interpolation){
    const int k = 5;
    mpz_t out, delta;
    mpz_inits(out, delta, NULL);
    signature_share_t S[k];

    mpz_fac_ui(delta, k);

    for(int i=0; i<k; i++) {
        S[i].id = TC_INDEX_TO_ID(i);
    }

    lagrange_interpolation(out, 1,k, S, delta);
    ck_assert(mpz_cmp_si(out, 600) == 0);
    lagrange_interpolation(out, 2,k, S, delta);
    ck_assert(mpz_cmp_si(out, -1200) == 0);
    lagrange_interpolation(out, 3,k, S, delta);
    ck_assert(mpz_cmp_si(out, 1200) == 0);
    lagrange_interpolation(out, 4,k, S, delta);
    ck_assert(mpz_cmp_si(out, -600) == 0);
    lagrange_interpolation(out, 5,k, S, delta);
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

START_TEST(test_verify){
    key_meta_info_t info;
    public_key_t public_key;

    init_key_meta_info(&info, 512, 3, 5);
    init_public_key(&public_key);

    key_share_t shares[info.l];
    init_key_shares(shares, &info);
    generate_keys(shares, &public_key, &info);

    mpz_t doc, signature;
    mpz_init(signature);
    mpz_init_set_str(doc, "95951009936565630770613232106413300773619435751148631183701517132539356488156", 10);

    signature_share_t signatures[info.l];
    for(int i=0; i<info.l; i++) {
        init_signature_share(signatures + i);
    }

    for (int i=0; i<info.l; i++) {
        node_sign(signatures + i, shares + i, doc, &public_key, &info);
        int verify = verify_signature(signatures + i, doc, &public_key, &info);
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
    init_key_meta_info(&info, 1024, 3, 5);
    init_public_key(&public_key);

    key_share_t shares[info.l];
    init_key_shares(shares, &info);
    generate_keys(shares, &public_key, &info);

    mpz_t doc;
    mpz_t signature;
    mpz_init(signature);
    mpz_init(doc);

    unsigned char document[] = "Hola mundo";
    unsigned char hash[32];
    MHASH sha = mhash_init(MHASH_SHA256);
    mhash(sha, document, 10);
    mhash_deinit(sha, hash);

    int hash_pkcs1_len = OCTET_SIZE(public_key.n);
    byte hash_pkcs1[hash_pkcs1_len];
    pkcs1_encoding(hash_pkcs1, hash, "SHA-256", hash_pkcs1_len);

    TC_GET_OCTETS(doc, hash_pkcs1_len, hash_pkcs1);

    signature_share_t signatures[info.l];
    for(int i=0; i<info.l; i++) {
        init_signature_share(signatures + i);
    }

    for (int i=0; i<info.l; i++) {
        node_sign(signatures + i, shares + i, doc, &public_key, &info);
        int verify = verify_signature(signatures + i, doc, &public_key, &info);
        ck_assert(verify);
    }

    join_signatures(signature, (const signature_share_t *)(signatures), info.k, doc, &public_key, &info);

    struct rsa_public_key nettle_pk;
    nettle_rsa_public_key_init(&nettle_pk);
    
    mpz_set(nettle_pk.n, public_key.n);
    mpz_set(nettle_pk.e, public_key.e);

    nettle_rsa_public_key_prepare(&nettle_pk);
    int result = nettle_rsa_sha256_verify_digest(&nettle_pk, hash, signature);

    ck_assert(result);

    nettle_rsa_public_key_clear(&nettle_pk);

    for(int i=0; i<info.l; i++) {
        clear_signature_share(signatures + i);
    }
    clear_key_shares(shares, &info);
    mpz_clears(doc, signature, NULL);
    clear_public_key(&public_key);
    clear_key_meta_info(&info);
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
    tcase_add_test(tc_core, test_verify);
    tcase_add_test(tc_core, test_verify_invert);
    tcase_add_test(tc_core, test_complete_sign);
    tcase_add_test(tc_core, test_poly_eval);
    tcase_add_test(tc_core, test_poly_eval_ui);
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
