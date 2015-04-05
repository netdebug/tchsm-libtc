CC=clang
CFLAGS=-std=c11 -Wall -Werror -g --coverage -O0 -fprofile-instr-generate -fcoverage-mapping
LDFLAGS=-lgmp -lcheck -lmhash --coverage -fprofile-instr-generate -ltcmalloc -lprofiler

OBJ=poly.o random.o init.o algorithms_generate_keys.o algorithms_join_signatures.o algorithms_node_sign.o algorithms_verify_signature.o check_algorithms.o
DEPS=%.h

all: $(OBJ)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

check_algorithms: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

check: check_algorithms
	./check_algorithms
	
clean:
	rm *.{o,gc{da,no}} 
