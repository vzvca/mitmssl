CC      ?= cc
CFLAGS  ?= -O2
CFLAGS  += -std=c11 -Wall -Wextra -D_GNU_SOURCE -I$(OPENSSL_INC)
LDLIBS   = -L$(OPENSSL_LIB) -lssl -lcrypto -lpthread

OPENSSL_INC ?= /tmp/openssl-3.5.7/include
OPENSSL_LIB ?= /tmp/openssl-lib

OBJS = src/main.o src/ca.o src/forge.o src/log.o src/conn.o \
       src/inspect.o src/exec.o
BIN  = mitmssl

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

src/%.o: src/%.c src/mitmssl.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)

.PHONY: all clean
