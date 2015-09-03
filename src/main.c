#define _GNU_SOURCE

#include "tc.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

static const char * _message = "Hello world";
static char * message;
static int key_size = 1024;
static int k=3;
static int l=5;

void set_parameters(int argc, char ** argv)
{

    message = strdup(_message);
#ifndef __CPROVER__
    int opt;
    while((opt = getopt(argc, argv, "m:k:l:s:")) != -1){
        switch(opt) {
            case 'm':
                free(message);
                message = strdup(optarg);
                break;
            case 'k':
                k = strtol(optarg, NULL, 10);
                break;
            case 'l':
                l = strtol(optarg, NULL, 10);
                break;
            case 's':
                key_size = strtol(optarg, NULL, 10);
                break;
        }
    }
#endif
}


int main(int argc, char ** argv)
{ 
    set_parameters(argc, argv);
    char * b64;

    key_metainfo_t * info;
    key_share_t ** shares = tc_generate_keys(&info, 512, k, l);

    bytes_t * doc = tc_init_bytes( message, strlen(message));
    bytes_t * doc_pkcs1 = tc_prepare_document(doc, TC_SHA256, info);

    b64 = tc_bytes_b64(doc_pkcs1);
    printf("Document: %s\n", b64);
    free(b64);

    signature_share_t * signatures[l];

    for (int i=0; i<l; i++) {
        signatures[i] = tc_node_sign(shares[i], doc_pkcs1, info);
        int verify = tc_verify_signature(signatures[i], doc_pkcs1, info);
        assert(verify);
    }

    bytes_t * signature = tc_join_signatures((void*) signatures, doc_pkcs1, info);
    int verify = tc_rsa_verify(signature, doc, info, TC_SHA256);
    assert(verify);

    b64 = tc_bytes_b64(signature);
    printf("Signature: %s\n", b64);
    free(b64);


    tc_clear_bytes_n(doc, doc_pkcs1, NULL);
    tc_clear_bytes(signature);
    for(int i=0; i<l; i++) {
        tc_clear_signature_share(signatures[i]);
    }
    tc_clear_key_shares(shares, info);
    tc_clear_key_metainfo(info);
}
