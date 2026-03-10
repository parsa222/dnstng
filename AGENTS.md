# AGENTS.md — AI Agent Onboarding Guide

This file is for AI coding agents picking up this project. Read this first, then read
`TODO.md` for the task list and `ARCHITECTURE.md` for the technical deep-dive.

---

## What This Project Is

DnstTNG (DNS Tunnel New Generation) is a bidirectional DNS tunneling system written in C11.
It tunnels arbitrary TCP traffic through DNS queries, using every available field in the DNS
protocol plus three backup channels (SMTP, OCSP, CRL) for when DNS is blocked.

The immediate target environment is the IRGFW (Iran's national filtering system), which
blocks VPNs via DPI, drops TXT-record tunnels, and flags high-entropy subdomains.

Two binaries are produced: `dnstunnel-client` and `dnstunnel-server`.

---

## Project State

The core infrastructure and Priority 1 integration are complete.

### What is fully implemented and tested

- `common/encode.c` — Base36 / Base32 encoding
- `common/transport.c` — Reliability layer (seq/ack/retransmit/CRC/sliding window)
- `common/dns_packet.c` — DNS wire protocol: query builder, response builder, full parser,
  RDATA builders for NAPTR, SRV, CAA, SOA, SVCB, HINFO
- `common/channel.c` — Multi-channel pack/unpack across NAPTR, CAA, SRV, SOA, Auth NS,
  Additional glue, EDNS0 option 65001, TTL steganography
- `common/compress.c` — LZ4 wrapper
- `common/config.c` — Config file parser for both client and server
- `common/log.c` — Logging
- `common/stealth.c` — Jitter, noise domain generation, entropy measurement
- `common/smtp_channel.c` — SMTP backup tunnel (libuv TCP)
- `common/ocsp_channel.c` — OCSP covert channel (HTTP GET)
- `common/crl_channel.c` — CRL covert channel (HTTP GET)
- `server/chain.c` — CNAME chain and NS referral chain build/parse
- **`server/tunnel_server.c`** — Multi-channel response (channel_pack + chain build),
  SYN-ACK with negotiated channel bitmask
- **`client/tunnel_client.c`** — Multi-channel unpack (channel_unpack + chain parse),
  SYN with channel bitmask, SYN-ACK channel negotiation
- **`server/dns_server.c`** — `dns_server_send_raw()` for pre-built DNS packets
- All 6 tests in `tests/` pass (including `test_integration`)

### What remains (Priority 2+)

See `TODO.md` for Priority 2 spec-required features and Priority 3 future ideas.
The channel/chain/backup code is now fully wired into the tunnel data path.
Backup channels (SMTP, OCSP, CRL) are implemented as standalone modules but not yet
connected to the client session fallback logic (TODO #18).

---

## Directory Map

```
common/         Shared library: all protocol code. Built as common_lib.
  channel.c/h   Multi-channel pack/unpack (the core of what makes this different)
  chain.c/h     CNAME and NS referral chaining (lives here, used by server)
  dns_packet.c/h DNS wire format, all RDATA builders, full response parser
  transport.c/h  Reliability layer: headers, seq/ack/retransmit, sliding window
  encode.c/h    Base36 / Base32
  compress.c/h  LZ4 wrapper
  config.c/h    INI-style config parser, client_config_t and server_config_t
  smtp_channel.c/h  SMTP backup tunnel
  ocsp_channel.c/h  OCSP backup channel
  crl_channel.c/h   CRL backup channel
  stealth.c/h   Jitter, noise domains, entropy
  log.c/h       Logging (log_level_t: LOG_DEBUG/INFO/WARN/ERROR)
  util.c/h      err_t error codes, CRC16-CCITT, safe_copy

client/
  main.c        CLI, loads config, starts libuv loop
  socks5.c/h    SOCKS5 proxy listener (RFC 1928)
  tunnel_client.c/h  Session management, DNS query dispatch
  check.c/h     --check (channel probe) and --benchmark modes

server/
  main.c        CLI, loads config, starts libuv loop
  dns_server.c/h     UDP DNS listener (libuv)
  tunnel_server.c/h  Session management, responds to queries
  proxy.c/h     TCP exit-node proxy

tests/
  test_encode.c
  test_transport.c
  test_dns_packet.c
  test_channel.c
  test_chain.c
  test_integration.c
  run_tests.sh
```

---

## Coding Conventions

**These are hard rules. Do not break them.**

1. **C11 standard only.** `gcc -std=c11 -Wall -Wextra -Werror -pedantic` must produce zero
   warnings and zero errors.

2. **No global variables** except `log_level` in `log.c`. All state lives in `*_ctx_t` or
   `*_config_t` structs passed explicitly.

3. **All functions that can fail return `err_t`** (from `util.h`). Never ignore return values.
   For functions that return a count (like `channel_pack`), negative means error.

4. **Explicit bounds checks on every buffer.** Never write past the end of a buffer.
   Use `safe_copy()` from `util.h` for raw copies. Use the `*_cap` convention: the caller
   passes `buf` and `buf_cap`; the function checks before writing.

5. **No malloc without a corresponding free path.** If a struct owns heap memory, it must have
   a `_free()` function. Document the owner.

6. **`typedef struct { ... } thing_t;`** naming convention throughout.

7. **All network-facing parsing is defensive.** Treat all incoming bytes as potentially
   malicious. Return `ERR_PROTO` on any malformed input rather than crashing.

8. **Sizes are `size_t`.** Never use `int` for buffer sizes or lengths.

9. **libuv for all I/O.** No raw `pthread`, `select`, `epoll`. The event loop is `uv_loop_t`.

---

## How to Build

```bash
# Dependencies (Ubuntu 20.04 / 22.04 / 24.04)
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config \
    libuv1-dev libc-ares-dev liblz4-dev

# Quick build (installs deps, compiles, runs tests)
./build.sh

# Or manual build with GNU Make
make clean && make all

# Or manual build with CMake
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

The build produces `dnstunnel-client` and `dnstunnel-server` in `build/`.

For ASan (AddressSanitizer — required to pass before merging):
```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-fsanitize=address -g"
make -j$(nproc)
```

---

## How to Run Tests

```bash
cd build
ctest --output-on-failure
# or directly:
./test_encode && ./test_transport && ./test_dns_packet && ./test_channel && ./test_chain && ./test_integration
```

All 6 test binaries must pass before any PR is considered ready.

---

## Key Data Structures to Know

### `transport_ctx_t` (`common/transport.h`)
The reliability layer state. One per session (both client and server). Tracks next sequence
number, ack sequence, a 64-slot ring buffer for retransmission, and `active_channels`
(bitmask of `CHAN_*` flags negotiated for this session).

### `channel_buf_t` (`common/channel.h`)
Stack-allocated working buffer for `channel_pack()` / `channel_unpack()`. About 100KB.
Initialize with `channel_buf_init(cb, active_channels, domain)` before each use.
Contains pre-allocated arrays for all answer/NS/additional records plus scratch rdata space.

### `dns_parsed_response_t` (`common/dns_packet.h`)
Output of `dns_parse_response_full()`. Holds up to 128 RRs (answer + authority + additional),
EDNS0 option data, TXID, and question type.

### `dns_response_ext_t` (`common/dns_packet.h`)
Input to `dns_build_response_ext()`. Carries all sections (answers, auth NS names, additional
glue, EDNS0 option) in a single struct. `channel_buf_t` embeds one of these as `cb->resp`.

### `client_config_t` / `server_config_t` (`common/config.h`)
Configuration for client and server. Key fields: `domain`, `resolver`, `listen_addr/port`,
`active_channels` (bitmask), `cname_chain_depth`, `ns_chain_depth`, `ttl_encoding`,
and backup channel host/port fields.

### `tunnel_header_t` (`common/transport.h`)
6-byte packed header on every transport packet: `session_id`, `seq_num`, `ack_num`,
`checksum` (CRC16-CCITT), `flags` (`TUNNEL_FLAG_SYN/ACK/FIN/DATA/POLL`), `payload_len`.

---

## Critical Contracts — Do Not Break

1. **Fragment header format** (`channel.c` ↔ `channel_unpack`):
   Every rdata payload begins with a 3-byte header: `[offset_hi, offset_lo, frag_len]`.
   `channel_pack` writes it; `channel_unpack` reads it. Changing this breaks all sessions.

2. **CNAME target format** (`chain.c`):
   `{base36_data}.c{i}.t.{domain}` — the `.c{i}.t.` infix is how the parser identifies
   CNAME chain links. NS referral format: `{base36_data}.ns{i}.{domain}`.

3. **EDNS0 option code 65001** (`dns_packet.h: EDNS0_TUNNEL_OPTION`):
   Used by both upstream (client embed) and downstream (server embed). Code must match
   on both sides.

4. **`channel_buf_t` must not be moved after `channel_buf_init()`** because `cb->resp` holds
   raw pointers into `cb->answers`, `cb->ns_name_ptrs`, and `cb->addl`.

5. **libuv handle types (`uv_tcp_t` etc.) must not be moved in memory after `uv_*_init()`.**
   This applies to the backup channel structs. Allocate on heap if needed.

---

## Where to Start

1. Read `TODO.md` — Priority 1 is done; Priority 2 has the remaining spec-required features.
2. Read `ARCHITECTURE.md` — understand the data flow.
3. Run the tests first to confirm the baseline is clean (`make tests` or `./build.sh`).
4. The integration test (`tests/test_integration.c`) is the best starting point for
   understanding how all the pieces fit together.

### Channel negotiation wire format

SYN payload: 4 bytes big-endian `CHAN_*` bitmask (client's supported channels).
SYN-ACK payload: 4 bytes big-endian `CHAN_*` bitmask (intersection of client+server).

---

## Files That Should Not Be Modified Without Good Reason

| File | Why |
|------|-----|
| `common/transport.h` | The packed `tunnel_header_t` is a wire format; changing it breaks existing sessions |
| `common/util.h` | `err_t` values are used everywhere; adding codes is fine, changing existing ones is not |
| `common/dns_packet.h` | `CHAN_*` flag values are stored in config and session state; don't renumber |
| `LTMemory.MD` | The original specification; edit only to note deviations, not to change the spec |
