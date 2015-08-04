#define _GNU_SOURCE

#include "tc.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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

static void print_bytes(bytes_t bytes) 
{
#ifdef __CPROVER__
    __CPROVER_assume(bytes.data_len < 1024);
#endif
    for(int i=0; i<bytes.data_len; i++) {
        printf("%1X", bytes.data[i]);
    }
}


int main(int argc, char ** argv)
{ 
    set_parameters(argc, argv);

    key_meta_info_t * info;
    key_share_t ** shares = tc_generate_keys(&info, key_size, k, l);

    printf("Message: %s\n", message);
    bytes_t * doc = tc_init_bytes((void*) message, strlen(message));
    bytes_t * doc_pkcs1 = tc_prepare_document(doc, TC_SHA256, info);
    printf("Hashed Message: "); print_bytes(*doc_pkcs1); printf("\n");

    signature_share_t ** signatures = malloc(l*sizeof(signature_share_t*));

    for (int i=0; i<l; i++) {
        signatures[i] = tc_node_sign(shares[i], doc_pkcs1, info);
        if(!tc_verify_signature(signatures[i], doc_pkcs1, info))
            abort();
    }

    bytes_t * signature = tc_join_signatures((const signature_share_t**) signatures, doc_pkcs1, info);
    printf("Signature: "); print_bytes(*signature); printf("\n");

    tc_clear_bytes_n(signature, doc_pkcs1, doc, NULL);
    for(int i=0; i<l; i++) {
        tc_clear_signature_share(signatures[i]);
    }
    free(signatures);
    tc_clear_key_shares(shares, info);
    tc_clear_key_meta_info(info);
}
