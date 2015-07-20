#ifndef TC_INTERNAL_H
# define TC_INTERNAL_H

#include <gmp.h>

#define TC_OCTET_SIZE(z) ((mpz_sizeinbase(z, 2) + 7) / 8)
#define TC_GET_OCTETS(z, bcount, op) mpz_import(z, bcount, 1, 1, 0, 0, op)
#define TC_TO_OCTETS(count, op) mpz_export(NULL, count, 1, 1, 0, 0, op)
#define TC_ID_TO_INDEX(id) (id-1)
#define TC_INDEX_TO_ID(idx) (idx+1)

#define TC_MPZ_TO_BYTES(bytes, z) \
    do { (bytes).data = TC_TO_OCTETS(&(bytes).data_len, z); } while(0)
#define TC_BYTES_TO_MPZ(z, bytes) \
    do { TC_GET_OCTETS(z, (bytes).data_len, (bytes).data); } while(0)

#endif
