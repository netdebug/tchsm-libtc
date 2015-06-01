CC=clang
CFLAGS=-std=c11 -Wall -g -O0
EXTRACFLAGS=
LDFLAGS=-lgmp -lcheck -lmhash -lnettle -lhogweed
EXTRALDFLAGS=

OBJ=poly.o random.o init.o algorithms_generate_keys.o algorithms_join_signatures.o algorithms_node_sign.o algorithms_verify_signature.o check_algorithms.o algorithms_pkcs1_encoding.o
DEPS=%.h

all: $(OBJ)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

check_algorithms: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

check: check_algorithms
	./check_algorithms
	
clean:
	rm *.o check_algorithms
