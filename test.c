#include <stdio.h>
#include <gmp.h>

#include "tcb.h"
#include "algorithms.h"


int main() {
    key_meta_info_t info;
    public_key_t public_key;
    init_key_meta_info(&info, 1024, 3, 5);
    init_public_key(&public_key);

    key_share_t * shares = generate_keys(&info, &public_key);

    mpz_t doc;
    mpz_t signature;
    mpz_inits(doc, signature, NULL);
    char * document = "Hola mundo!";
    mpz_import(doc, 11, 1, 1, 1, 0, document);
    printf("%s = ", document);
    mpz_out_str(stdout, 62, doc);
    printf("\n");
    signature_share_t signatures[5];

    for (int i=0; i<5; i++) {
        init_signature_share(&signatures[i]);
        node_sign(&signatures[i], i, &shares[i], &public_key, &info, doc);
    }

    for (int i=0; i<5; i++) {
        printf("s[%d]=", i);
        mpz_out_str(stdout, 62, signatures[i].signature);
        printf("\n");
        clear_signature_share(&signatures[i]);
    }

#if 1
    join_signatures(signature, doc, signatures, 5, &public_key, &info);
    printf("signature=");
    mpz_out_str(stdout, 62, signature);
    printf("\n");
#endif
    clear_shares(shares, &info);
    mpz_clears(doc, signature, NULL);
    clear_public_key(&public_key);
    clear_key_meta_info(&info);

    return 0;
}
