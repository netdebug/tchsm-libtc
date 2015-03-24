CC=clang
CFLAGS=-I../include -std=c11 -Wall -Werror -g
LDFLAGS=-lgmp -lcheck -lmhash -lhogweed -lnettle

OBJ = poly.o random.o init.o algorithms.o algorithms_check.o
DEPS = ../include/%.h

all: $(OBJ)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

check_algorithms: $(OBJ)
	@echo $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

check: check_algorithms
	./check_algorithms
	
clean:
	rm *.o
