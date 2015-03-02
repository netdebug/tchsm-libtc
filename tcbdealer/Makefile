CC=gcc
CFLAGS=-c -Wall -std=c11 -I../include -g
OBJS=algorithms.o
LIBNAME=libtcbdealer.a

all: $(LIBNAME)

$(LIBNAME): $(OBJS)
	ar rcs $@ $^
	
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
	
clean:
	rm *.o *.a