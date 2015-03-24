#include <stdio.h>
#include <stdlib.h>
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
    mpz_init(signature);
    mpz_init_set_str(doc, "95951009936565630770613232106413300773619435751148631183701517132539356488156", 10);

    gmp_printf("doc = %Zd\n", doc);

    signature_share_t ** signatures = create_signature_shares(&info);;

    for (int i=0; i<5; i++) {
        node_sign(signatures[i], i, &(shares[i]), &public_key, &info, doc);
        gmp_printf("s[%d] = %Zd\n", i, signatures[i]->signature);
        int verify = verify_signature(signatures[i], doc, &public_key, &info, i);
        printf("Verification=%s\n", verify ? "true" : "false");
    }

    
    join_signatures(signature, doc, (const signature_share_t **)(signatures), 5, &public_key, &info);
    gmp_printf("signature = %Zd\n", signature);

    destroy_signature_shares(signatures, &info);
    clear_shares(shares, &info);
    mpz_clears(doc, signature, NULL);
    clear_public_key(&public_key);
    clear_key_meta_info(&info);

    return 0;
}
