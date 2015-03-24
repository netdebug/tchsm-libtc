#include <stdlib.h>
#include <check.h>
#include <gmp.h>
#include <algorithms.h>
#include <mathutils.h>
#include <tcb.h>
#include <mhash.h>

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

    key_share_t * shares = generate_keys(&info, &pk);
    
    mpz_fac_ui(delta, info.l);

    mpz_mul(aux, delta, shares[0].s_i);
    mpz_mul_ui(d, aux, 2);
    mpz_mul(aux, delta, shares[1].s_i);
    mpz_sub(d, d, aux);

    mpz_mul(aux, d, pk.e);
    mpz_mod(aux, aux, pk.m);

    ck_assert(mpz_cmp_ui(aux, 1) == 0);

    mpz_clears(d, aux, delta, NULL);
    clear_key_meta_info(&info);    
    clear_public_key(&pk);

}
END_TEST

START_TEST(test_node_sign){
    key_meta_info_t info;
    public_key_t pk;

    init_public_key(&pk);
    init_key_meta_info(&info, 512, 2, 3);

    /* static keys, static document, looking for a result. */
    /* Normal case. */

    char * key_share1 = "2149010625129723869761566325717445711534088657873826912158887087211353174539591098886103272070189141366154332346676220575655136150208111986269738701603427";
    char * key_share2 = "2149010625129723869761566325717445711534088657873826912158887087211353174539591098886103272070189141366154332346676220575655136150208111986269738701603427";
    char * key_share3 = "2149010625129723869761566325717445711534088657873826912158887087211353174539591098886103272070189141366154332346676220575655136150208111986269738701603427";

    char * u = "1939678241071046324987185202564782815974840520578459781366491780840315429565293525904903712163291886074343125313091464502373141240025500515575282220735626303";
    
    char * n = "20534436295336470776576800387129875950424518956471686628384642351449136268340613797965405045736458998027599755316641385126893754450844151735860713689349793";
    char * m = "5133609073834117694144200096782468987606129739117921657096160587862284067085074880997948476996907304863536859309179430087056381772911166530778749592804177";
    char * e = "65537";

    key_share_t kshares[3];
    mpz_init_set_str(kshares[0].s_i, key_share1, 10);
    mpz_init_set_str(kshares[1].s_i, key_share2, 10);
    mpz_init_set_str(kshares[2].s_i, key_share3, 10);

    mpz_init_set_str(kshares[0].n, n, 10);
    mpz_init_set_str(kshares[1].n, n, 10);
    mpz_init_set_str(kshares[2].n, n, 10);

    mpz_init_set_str(info.vk_u, u, 10);
    mpz_init_set_str(pk.n, n, 10);
    mpz_init_set_str(pk.m, m, 10);
    mpz_init_set_str(pk.e, e, 10);

    signature_share_t ** sshares = create_signature_shares(&info);

    mpz_t x;
    mpz_init_set_str(x, "95951009936565630770613232106413300773619435751148631183701517132539356488156", 10);

    for(int i=0; i<3; i++) {
        node_sign(sshares[i], i, &(kshares[i]), &pk, &info, x);
    }

    mpz_t tsshare0, tsshare1, tsshare2;
    mpz_init_set_str(tsshare0, "9947859024344783701497430853144659183718380502035688538606116553149245304888637489739956616554224442527539465004985320279343187832848340961090149421152714", 10);
    mpz_init_set_str(tsshare1, "9947859024344783701497430853144659183718380502035688538606116553149245304888637489739956616554224442527539465004985320279343187832848340961090149421152714", 10);
    mpz_init_set_str(tsshare2, "9947859024344783701497430853144659183718380502035688538606116553149245304888637489739956616554224442527539465004985320279343187832848340961090149421152714", 10);
    ck_assert(mpz_cmp(sshares[0]->signature, tsshare0) == 0);
    ck_assert(mpz_cmp(sshares[1]->signature, tsshare1) == 0);
    ck_assert(mpz_cmp(sshares[2]->signature, tsshare2) == 0);


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
    tcase_add_test(tc_core, test_node_sign);
    suite_add_tcase(s, tc_core);

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

