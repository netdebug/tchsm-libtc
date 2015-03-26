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

/* TODO! */
#if 0
START_TEST(test_lagrange_interpolation){
    
}
END_TEST
#endif

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

