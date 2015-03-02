CC=gcc
CFLAGS=-I../include -std=c11 -Wall -Werror -g

OBJS: poly.o random.o init.o algorithms.o
DEPS: ../include/%.h

all: $(OBJS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
clean:
	rm *.o
