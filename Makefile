CC       ?= cc
CFLAGS   ?= -O2
CFLAGS   += -std=c11 -Wall -Wextra -D_GNU_SOURCE

# OpenSSL submodule (tag openssl-3.5.7), built statically inside the tree.
# Run `git submodule update --init` before building.
OPENSSL_DIR ?= openssl
OPENSSL_INC  = $(OPENSSL_DIR)/include
OPENSSL_LIB  = $(OPENSSL_DIR)

OBJS = src/main.o src/ca.o src/forge.o src/conn.o \
       src/inspect.o src/output.o
BIN  = mitmssl

ifeq ($(wildcard $(OPENSSL_DIR)/Configure),)
$(error OpenSSL submodule missing; run: git submodule update --init)
endif

all: $(BIN)

$(OPENSSL_DIR)/libcrypto.a: $(OPENSSL_DIR)/Configure
	cd $(OPENSSL_DIR) && \
	    ./Configure linux-x86_64 no-shared no-tests no-docs && \
	    $(MAKE) -j$$(nproc)

$(BIN): $(OBJS) $(OPENSSL_DIR)/libcrypto.a
	$(CC) $(CFLAGS) -I$(OPENSSL_INC) -o $@ $(OBJS) \
	    -L$(OPENSSL_LIB) -lssl -lcrypto -lpthread -ldl

src/%.o: src/%.c src/mitmssl.h
	$(CC) $(CFLAGS) -I$(OPENSSL_INC) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)

distclean: clean
	cd $(OPENSSL_DIR) && $(MAKE) distclean 2>/dev/null; true

.PHONY: all clean distclean
