CFLAGS = -std=c11 -Wall -g -O0
LDFLAGS = -lmhash -lgmp

CC = clang
AR = ar
RM = rm -f
RANLIB = ranlib

# Do not touch anything hereover

UNAME_S = $(shell sh -c 'uname -s 2>/dev/null || echo not')

EXE=
LIB_OBJ=
LIB_H=

LIB_FILE=libtc.a

LIB_H += mathutils.h
LIB_H += tc.h
LIB_H += tc_internal.h

LIB_OBJ += poly.o 
LIB_OBJ += random.o 
LIB_OBJ += init.o 
LIB_OBJ += algorithms_generate_keys.o
LIB_OBJ += algorithms_join_signatures.o
LIB_OBJ += algorithms_node_sign.o
LIB_OBJ += algorithms_verify_signature.o
LIB_OBJ += algorithms_pkcs1_encoding.o
LIB_OBJ += algorithms_rsa_verify.o
LIB_OBJ += algorithms_base64.o

CHECK_LDFLAGS= -lcheck
ifdef NO_CHECK
	CFLAGS += -DNO_CHECK
else
    EXE += check_algorithms
    CFLAGS += $(shell pkg-config --cflags check)
    LDFLAGS += $(shell pkg-config --libs check) 
endif

EXE += main

ifeq ($(UNAME_S),Linux)
    LDFLAGS += -lm
endif
ifeq ($(UNAME_S),Darwin)
    ifeq ($(shell test -d /opt/local/lib && echo y),y)
    	CFLAGS += -I/opt/local/include
	LDFLAGS += -L/opt/local/lib
    endif
endif

all: $(LIB_FILE) $(EXE)
 
$(LIB_FILE): $(LIB_OBJ)
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@

$(LIB_OBJ): $(LIB_H)

check_algorithms: check_algorithms.o $(LIB_FILE) 
	$(CC) -o $@ $^ $(LDFLAGS) 
	
main: main.o $(LIB_FILE)
	$(CC) -o $@ $^ $(LDFLAGS)

ifndef NO_CHECK
check: check_algorithms
	./$^
endif

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	$(RM) $(LIB_FILE) $(LIB_OBJ) $(EXE)
