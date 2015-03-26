CC=gcc
CFLAGS=-I../include -std=c11 -Wall -Werror -g -fprofile-arcs -ftest-coverage
LDFLAGS=-lgmp -lcheck -lmhash -lgcov

OBJ=poly.o random.o init.o algorithms_generate_keys.o algorithms_join_signatures.o algorithms_node_sign.o algorithms_verify_signature.o check_algorithms.o
DEPS=%.h

all: $(OBJ)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

check_algorithms: $(OBJ)
	@echo $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

check: check_algorithms
	./check_algorithms
	
clean:
	rm *.o *.gc{da,no}
