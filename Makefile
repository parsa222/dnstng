# ─────────────────────────────────────────────────────────────────────────────
# DnstTNG – GNU Makefile
#
# Targets:
#   all        (default) build dnstunnel-client and dnstunnel-server
#   tests      build and run all unit tests
#   asan       rebuild everything with AddressSanitizer into build_asan/
#   clean      remove build/ and build_asan/
#   install    install binaries to $(PREFIX)/bin  [default: /usr/local]
#   uninstall  remove installed binaries
#
# Build type:
#   make                 → debug build  (-g -O0)
#   make BUILD=release   → release build (-O2)
# ─────────────────────────────────────────────────────────────────────────────

CC  := gcc
AR  := ar

STD  := -std=c11
WARN := -Wall -Wextra -Werror -pedantic
DEFS := -D_GNU_SOURCE

BUILD ?= debug
ifeq ($(BUILD),release)
    OPT := -O2
else
    OPT := -g -O0
endif

CFLAGS  := $(STD) $(WARN) $(DEFS) $(OPT)
LDFLAGS :=

# ── External libraries via pkg-config ─────────────────────────────────────────
LIBUV_CFLAGS := $(shell pkg-config --cflags libuv)
LIBUV_LIBS   := $(shell pkg-config --libs   libuv)
CARES_CFLAGS := $(shell pkg-config --cflags libcares)
CARES_LIBS   := $(shell pkg-config --libs   libcares)
LZ4_CFLAGS   := $(shell pkg-config --cflags liblz4)
LZ4_LIBS     := $(shell pkg-config --libs   liblz4)

PKG_CFLAGS := $(LIBUV_CFLAGS) $(CARES_CFLAGS) $(LZ4_CFLAGS)
PKG_LIBS   := $(LIBUV_LIBS) $(CARES_LIBS) $(LZ4_LIBS) -lm

# ── Include search paths (superset; harmless for all units) ───────────────────
INCS := -Icommon -Ithird_party -Iserver -Iclient

# ── Build directory ───────────────────────────────────────────────────────────
BUILD_DIR := build

# ── Sources ───────────────────────────────────────────────────────────────────
COMMON_SRCS := $(wildcard common/*.c) third_party/lz4.c

CLIENT_SRCS := client/main.c \
               client/socks5.c \
               client/tunnel_client.c \
               client/check.c \
               server/chain.c

SERVER_SRCS := server/main.c \
               server/dns_server.c \
               server/tunnel_server.c \
               server/proxy.c \
               server/chain.c

# Tests that link only against the common library
TEST_SRCS := tests/test_encode.c \
             tests/test_transport.c \
             tests/test_dns_packet.c \
             tests/test_channel.c

# test_chain also needs server/chain.c (not part of common_lib)
TEST_CHAIN_SRC := tests/test_chain.c

# test_integration also needs server/chain.c
TEST_INTEGRATION_SRC := tests/test_integration.c

# ── Object files ──────────────────────────────────────────────────────────────
COMMON_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(COMMON_SRCS))
CLIENT_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(CLIENT_SRCS))
SERVER_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SERVER_SRCS))

# ── Outputs ───────────────────────────────────────────────────────────────────
COMMON_LIB     := $(BUILD_DIR)/libcommon.a
CLIENT_BIN     := $(BUILD_DIR)/dnstunnel-client
SERVER_BIN     := $(BUILD_DIR)/dnstunnel-server
TEST_BINS      := $(patsubst tests/%.c,$(BUILD_DIR)/%,$(TEST_SRCS))
TEST_CHAIN_BIN       := $(BUILD_DIR)/test_chain
TEST_INTEGRATION_BIN := $(BUILD_DIR)/test_integration
ALL_TEST_BINS  := $(TEST_BINS) $(TEST_CHAIN_BIN) $(TEST_INTEGRATION_BIN)

# ── Default target ────────────────────────────────────────────────────────────
.PHONY: all
all: $(CLIENT_BIN) $(SERVER_BIN)

# ── AddressSanitizer build (into build_asan/) ─────────────────────────────────
.PHONY: asan
asan:
	$(MAKE) all BUILD_DIR=build_asan \
	    CFLAGS="$(CFLAGS) -fsanitize=address" \
	    LDFLAGS="$(LDFLAGS) -fsanitize=address"

# ── Static common library ─────────────────────────────────────────────────────
$(COMMON_LIB): $(COMMON_OBJS)
	$(AR) rcs $@ $^

# ── Client binary ─────────────────────────────────────────────────────────────
$(CLIENT_BIN): $(CLIENT_OBJS) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ $^ $(PKG_LIBS)

# ── Server binary ─────────────────────────────────────────────────────────────
$(SERVER_BIN): $(SERVER_OBJS) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ $^ $(PKG_LIBS)

# ── Test binaries (single-source, link against common_lib) ────────────────────
$(TEST_BINS): $(BUILD_DIR)/test_%: tests/test_%.c $(COMMON_LIB)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCS) $(PKG_CFLAGS) $(LDFLAGS) -o $@ $^ $(PKG_LIBS)

# test_chain needs server/chain.c compiled inline (mirrors CMakeLists.txt)
$(TEST_CHAIN_BIN): $(TEST_CHAIN_SRC) server/chain.c $(COMMON_LIB)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCS) $(PKG_CFLAGS) $(LDFLAGS) -o $@ $^ $(PKG_LIBS)

# test_integration needs server/chain.c for chain_parse_* functions
$(TEST_INTEGRATION_BIN): $(TEST_INTEGRATION_SRC) server/chain.c $(COMMON_LIB)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCS) $(PKG_CFLAGS) $(LDFLAGS) -o $@ $^ $(PKG_LIBS)

# ── Run all tests ─────────────────────────────────────────────────────────────
.PHONY: tests
tests: $(ALL_TEST_BINS)
	@for t in $(ALL_TEST_BINS); do \
	    echo "=== $$t ==="; \
	    $$t || exit 1; \
	done; \
	echo "All tests passed."

# ── Generic compile rule (preserves subdirectory structure in BUILD_DIR) ───────
$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCS) $(PKG_CFLAGS) -c -o $@ $<

# ── Clean ─────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) build_asan

# ── Install / uninstall ───────────────────────────────────────────────────────
PREFIX ?= /usr/local

.PHONY: install
install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(CLIENT_BIN) $(DESTDIR)$(PREFIX)/bin/
	install -m 755 $(SERVER_BIN) $(DESTDIR)$(PREFIX)/bin/

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/dnstunnel-client
	rm -f $(DESTDIR)$(PREFIX)/bin/dnstunnel-server
