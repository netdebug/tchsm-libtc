#include <stdlib.h>
#include <gmp.h>

#include "mathutils.h"
/** GMP-based polynomial library **/

typedef struct poly {
    mpz_t * coeff;
    int size;
} poly_t;

poly_t * create_random_poly(mpz_t d, int size, mpz_t m) {
    int i;
    
    poly_t * poly = malloc(sizeof(*poly));
    int bit_len = mpz_sizeinbase(m, 2);
    
    poly->size = size;
    mpz_t * coeff = malloc(size*sizeof(*coeff));
    
    mpz_init_set(coeff[0], d);
    for(i = 1; i<size; i++) {
        mpz_init(coeff[i]);
        random_dev(coeff[i], bit_len);
        mpz_mod(coeff[i], coeff[i], m);
    }
    poly->coeff = coeff;
    return poly;
}

void clear_poly(poly_t * poly) {
    int i;
    mpz_t * coeff = poly->coeff;
    
    for(i=0; i<poly->size; i++) {
        mpz_clear(coeff[i]);
    }
    free(coeff);
    free(poly);
}

// Unrolling the stack :)
void poly_eval(mpz_t rop, poly_t * poly, mpz_t op) {
    mpz_t * coeff = poly->coeff;
    int size = poly->size;
    
    mpz_t aux;
    mpz_init(aux);
    
    mpz_set(rop, coeff[size - 1]);
    
    int i;
    for(i=size - 2; i >= 0; i--) {        
        mpz_mul(aux, coeff[i], rop); 
        mpz_add(rop, op, aux);
    }
    
    mpz_clear(rop);
}

void poly_eval_ui(mpz_t rop, poly_t * poly, unsigned long op) {
    mpz_t x;
    mpz_init_set_ui(x, op);
    poly_eval(rop, poly, x);
    mpz_clear(x);    
}