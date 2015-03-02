#include <stdio.h>
#include <gmp.h>

#include "tcb.h"
#include "tcbdealer/algorithms.h"
#include "tcbnode/algorithms.h"


int main() {
    key_meta_info_t info;
    public_key_t public_key;
    init_key_meta_info(&info, 1024, 3, 5);
    init_public_key(&public_key);
    
    key_share_t * shares = generate_keys(&info, &public_key);
    
    unsigned char * document = "Hola mundo!";
    signature_share_t signatures[5];
    for (int i=0; i<5; i++) {
        init_signature_share(&signatures[i]);
        node_sign(&signatures[i], i, &shares[i], &public_key, document, 11);
    }
    
    for (int i=0; i<5; i++) {
        printf("s[%d]=", i);
        mpz_out_str(stdout, 62, signatures[i].signature);
        printf("\n");
        clear_signature_share(&signatures[i]);
    }
    
    clear_key_meta_info(&info);
    
    return 0;
}