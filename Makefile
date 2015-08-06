CC=clang
CFLAGS=-std=c11 -Wall -g
EXTRACFLAGS=
LDFLAGS=-lcheck -lmhash -lgmp -lm -lpthread -lrt
EXTRALDFLAGS=
RANLIB=ranlib

EXE=check_algorithms main
OBJ_LIB=libtc.a
OBJ=poly.o random.o init.o algorithms_generate_keys.o \
	algorithms_join_signatures.o algorithms_node_sign.o \
	algorithms_verify_signature.o algorithms_pkcs1_encoding.o \
	algorithms_rsa_verify.o
DEPS=%.h

all: $(OBJ_LIB) $(EXE)

libtc.a: $(OBJ)
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

check_algorithms: $(OBJ) check_algorithms.o
	$(CC) -o $@ $^ $(LDFLAGS)

main: $(OBJ) main.o
	$(CC) -o $@ $^ -lgmp -lmhash

check: check_algorithms
	./check_algorithms

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm *.o check_algorithms libtc.a
