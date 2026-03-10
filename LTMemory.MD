# Build a DNS Tunnel Tool in C — Full Spec

## Goal
Build a **bidirectional DNS tunneling system** with a **client** (runs inside a censored network) and a **server** (runs on an authoritative DNS nameserver outside the censored network). The purpose is to tunnel arbitrary TCP traffic (SOCKS5 proxy) over DNS queries through recursive resolvers that the client can reach.

## Critical Context
- The client is behind a **strict IP whitelist firewall** — it can ONLY reach domestic DNS resolvers
- Those domestic resolvers still perform **recursive resolution** to external authoritative nameservers
- This recursive resolution is the ONLY path to the outside internet
- **TXT records may be dropped/filtered** — the tool MUST NOT depend on TXT records alone
- The tool must be resilient, fast, and hard to fingerprint
- **Entire codebase in C (C11 standard)**

---

## Architecture

```
[Client in censored network]
    ↓ DNS query: <encoded-data>.tunnel.yourdomain.com
[Domestic recursive DNS resolver]  (whitelisted, not controlled by us)
    ↓ recursive lookup
[Our authoritative DNS server outside]  (server component)
    ↓ decodes query, proxies request, encodes response
[Domestic recursive resolver]
    ↓ returns DNS response
[Client] → decodes response → delivers data to local app
```

---

## Build & Dependencies

### Required Libraries
- **libuv** — async I/O event loop (DO NOT use raw pthreads for concurrency)
- **c-ares** or **ldns** — DNS packet parsing/crafting (DO NOT hand-roll DNS packet parsing)
- **lz4** — compression (use the single-file `lz4.c`/`lz4.h` bundled version)
- No other external dependencies

### Build System
- **CMake** (minimum 3.16)
- Must produce **two static binaries**: `dnstunnel-client` and `dnstunnel-server`
- Must compile cleanly with: `-Wall -Wextra -Werror -pedantic -std=c11`
- Must pass **AddressSanitizer** (`-fsanitize=address`) with zero errors
- Must pass **Valgrind** (`valgrind --leak-check=full`) with zero leaks
- Provide a `CMakeLists.txt` that fetches and statically links all dependencies

### Cross-Compilation
- Must cross-compile for at least:
  - `x86_64-linux-gnu`
  - `aarch64-linux-gnu` (ARM64, for Android/phones)
  - `x86_64-linux-musl` (fully static, no glibc dependency)
- Provide cross-compilation instructions in README

### Code Quality Rules
- **No raw malloc without a corresponding free path** — every allocation must have a clear owner and cleanup
- Use a consistent `ctx` pattern: all state lives in a struct, passed explicitly. No global variables except logging config
- **All buffers must have explicit bounds checks** — never write to a buffer without checking remaining capacity
- Use `size_t` for all sizes/lengths. Never use `int` for buffer sizes
- All network-facing parsing must be **defensive**: assume every incoming byte is malicious
- Every function that can fail must return an error code. No ignoring return values
- Use `typedef struct { ... } thing_t;` naming convention throughout

---

## Requirements

### 1. Multi-Record-Type Support (ALL Types)

The tool MUST support tunneling over ALL of these DNS record types and be able to **negotiate/fallback** between them:

#### Standard Record Types

| Record Type | Upstream (client→server) encoding | Downstream (server→client) capacity |
|---|---|---|
| **A** | data encoded in subdomain labels | 4 bytes per record (IPv4 address) |
| **AAAA** | data encoded in subdomain labels | 16 bytes per record (IPv6 address) |
| **CNAME** | data encoded in subdomain labels | ~253 bytes per record (domain name) |
| **MX** | data encoded in subdomain labels | ~253 bytes (name) + 2 bytes (preference) |
| **TXT** | data encoded in subdomain labels | ~255 bytes per record (text string) |
| **NULL** | data encoded in subdomain labels | up to 65535 bytes (if supported) |
| **PTR** | data encoded in subdomain labels | ~253 bytes per record (domain name) |

#### High-Bandwidth Record Types (CRITICAL — implement these)

| Record Type | Downstream capacity per record | Field breakdown |
|---|---|---|
| **NAPTR** | **~500+ bytes** | Order (2B) + Preference (2B) + Flags string (~1B) + Service string (~30B) + **Regexp string (~253B)** + **Replacement name (~253B)**. Encode data in Regexp and Replacement fields. This is the highest-bandwidth standard record type. Return multiple NAPTR records per response |
| **SRV** | **~260 bytes** | Priority (2B) + Weight (2B) + Port (2B) + Target name (~253B). 6 bytes of numeric fields that can encode data + domain name |
| **SOA** | **~526 bytes** | MNAME (~253B) + RNAME (~253B) + Serial (4B) + Refresh (4B) + Retry (4B) + Expire (4B) + Minimum (4B). Two full domain names + 20 bytes of integers |
| **CAA** | **~253 bytes** | Flags (1B) + Tag string (~15B) + Value string (~253B). Value field is free-text |
| **SVCB (type 64)** | **Variable, potentially largest** | Variable-length key-value SvcParams. Highest theoretical capacity. Only works with modern resolvers |
| **HTTPS (type 65)** | **Variable, potentially largest** | Same structure as SVCB. Test support at startup |
| **HINFO** | **~510 bytes** | CPU string (~255B) + OS string (~255B). Two free-text fields. Ancient, rarely filtered |
| **URI (type 256)** | **Variable, large** | Priority (2B) + Weight (2B) + Target URI (long string). Can carry a full URI |

**Upstream** (client to server): data is ALWAYS encoded in the **subdomain labels** of the query (e.g., `<base36chunk>.tunnel.yourdomain.com`). Max 63 bytes per label, max 253 bytes total FQDN.

**Downstream** (server to client): data is encoded in the **answer records** of the response. Capacity depends on record type.

**Record type preference order (by downstream capacity):**
```
NAPTR > SVCB/HTTPS > SOA > HINFO > NULL > TXT > URI > SRV > CAA > CNAME > MX > AAAA > A
```

The tool must:
- Auto-detect which record types work by probing at startup
- Prefer higher-bandwidth types per the order above
- Fallback gracefully if a record type starts getting dropped mid-session
- Allow manual override to force a specific record type
- Support switching record types mid-session without dropping data

---

### 2. Multi-Channel Encoding (Use ALL DNS Packet Fields)

Do NOT only encode data in QNAME (upstream) and Answer RDATA (downstream). Use **EVERY controllable field** in the DNS packet:

#### Upstream Extra Channels (client → server)

**Transaction ID (2 bytes per query):**
- Encode 2 bytes of tunnel data in the 16-bit TXID field
- Test at startup whether the domestic resolver preserves TXID or re-randomizes it
- If preserved → use as extra upstream channel (free +2 bytes per query)
- If not preserved → disable and use TXID normally

**EDNS0 OPT OPTION-DATA (variable bytes):**
- Include a custom EDNS0 option (code 65001, in the private range 65001-65534) in the client's OPT record
- Stuff upstream data into the option-data field
- Test at startup whether the resolver passes through unknown EDNS0 options
- If yes → significant extra upstream bandwidth

**QCLASS field (2 bytes):**
- Normally IN (1). Test whether setting to other values (CH=3, HS=4) still gets the query forwarded
- If yes → 2 extra bytes. If no → leave as IN

#### Downstream Extra Channels (server → client)

**Authority Section (NS records):**
- Server adds 2-4 NS records for the tunnel zone
- Encode data in the NS domain names (e.g., `<base36data>.ns.yourdomain.com`)
- Each NS name = ~253 bytes of data
- Resolvers MUST pass Authority section through — it's required by DNS protocol

**Additional Section (Glue records):**
- Server adds glue A/AAAA records for the NS records in Authority section
- A glue = 4 bytes, AAAA glue = 16 bytes per record
- More data fields that resolvers are required to pass through

**TTL Fields (4 bytes per record, steganographic):**
- Encode data in the TTL values of ALL records (Answer, Authority, Additional)
- Each TTL = 4 bytes = 32 bits
- Option 1 (stealthy): keep values in range 60-86400, encode ~16 bits per TTL
- Option 2 (max bandwidth): use full 32 bits if stealth is less critical
- Make this configurable: `ttl_encoding = stealth | full | disabled`

**Multiple Answer Records:**
- For A queries, return 10+ A records (each 4 bytes)
- For AAAA queries, return multiple records (each 16 bytes)
- For NAPTR, return 3-4 records (~500 bytes each = ~2000 bytes total)
- Combined with TTL encoding: 10 A records = 40B (IPs) + 40B (TTLs) = 80 bytes

**EDNS0 OPT OPTION-DATA (server response):**
- Server includes custom EDNS0 option (code 65001) with downstream data payload
- Same test as upstream — verify resolver passes it through

#### Channel Negotiation

The `--check` mode MUST test each extra channel independently:
```
1. Send query with data encoded in TXID → verify server received it correctly
2. Send query with EDNS0 custom option → verify server received option data
3. Send query with non-standard QCLASS → verify server received it
4. Receive response → verify Authority section NS names arrive intact
5. Receive response → verify Additional section glue records arrive intact
6. Receive response → verify TTL values arrive unmodified
7. Receive response → verify EDNS0 OPT options in response arrive intact
8. Receive response → verify multiple answer records all arrive
```

For each channel that works → enable it. For each that's stripped/modified → disable it. Log results clearly. Store working channel set in session state.

---

### 3. CNAME Chaining (Downstream Bandwidth Multiplier)

This is a critical technique: **one client query can trigger multiple recursive lookups**, each carrying data.

**How it works:**
```
Client queries: x.tunnel.yourdomain.com A
                         ↓
Your NS responds: CNAME → data1.tunnel.yourdomain.com
                         ↓ (resolver automatically follows)
Your NS responds: CNAME → data2.tunnel.yourdomain.com
                         ↓ (resolver automatically follows)
Your NS responds: CNAME → data3.tunnel.yourdomain.com
                         ↓ (resolver automatically follows)
Your NS responds: A 1.2.3.4 (final answer, also carries data)

Result: 1 client query → 4 server-side responses → 4x downstream data
```

Implementation:
- Configurable chain depth (default 3, max 8)
- Too deep and resolvers may give up or return SERVFAIL — test max working depth at startup
- Each CNAME target name encodes a chunk of downstream data
- The final response (A/AAAA) also carries data
- Client parses the full CNAME chain from the response to extract all chunks
- Fall back to shorter chains if the resolver truncates

**NS Referral Chaining (alternative multiplier):**
- Server responds with NS referral to another NS under your control instead of a direct answer
- Resolver follows the delegation, triggering another recursive lookup
- Similar multiplier effect but via delegation instead of CNAME
- More stealthy — looks like normal DNS delegation behavior
- Implement as an alternative to CNAME chaining, selectable in config

---

### 4. EDNS0 Support
- Use EDNS0 to request larger UDP response sizes (up to 4096 bytes)
- Probe whether EDNS0 works at startup; fall back to 512-byte classic DNS if not
- Test multiple sizes: 4096, 2048, 1232, 512 — find the max that works
- This significantly increases downstream bandwidth for ALL record types

---

### 5. Encoding

**Upstream (subdomain encoding):**
- Use **Base36** (a-z, 0-9) as default — looks like normal subdomain characters, low entropy
- Also support Base32 as fallback
- Do NOT use Base64 — capital letters and special chars look suspicious in DNS labels
- Each label max 63 chars, total FQDN max 253 chars
- Structure: `<seq>.<chunk1>.<chunk2>.<chunk3>.tunnel.yourdomain.com`

Implement encoding as a clean module:
```c
// encode.h
typedef enum { ENCODE_BASE36, ENCODE_BASE32 } encode_mode_t;

size_t encode_data(const uint8_t *in, size_t in_len,
                   char *out, size_t out_cap,
                   encode_mode_t mode);

size_t decode_data(const char *in, size_t in_len,
                   uint8_t *out, size_t out_cap,
                   encode_mode_t mode);
```

**Downstream (response encoding):**
- Binary packing for A/AAAA records and numeric fields (TTL, priority, weight, port, etc.)
- Base36/Base32 encoded domain names for CNAME/MX/NS/NAPTR replacement/SRV target
- Raw text for TXT/NAPTR regexp/CAA value/HINFO strings
- Raw binary for NULL records
- Full 32-bit encoding for TTL fields (when configured)

**Compression:**
- Apply LZ4 compression to all payloads BEFORE encoding (fast, low overhead)
- Use bundled `lz4.c`/`lz4.h` (single-file distribution)
- Negotiate compression support at session start

---

### 6. Reliability Layer
Since DNS is unreliable (UDP, queries can be dropped, reordered, duplicated):

Implement as a clean transport layer module:
```c
// transport.h
typedef struct {
    uint16_t session_id;
    uint16_t seq_num;
    uint16_t ack_num;
    uint16_t checksum;    // CRC16-CCITT
    uint8_t  flags;       // SYN, ACK, FIN, DATA, POLL
    uint8_t  payload[];
} __attribute__((packed)) tunnel_header_t;
```

- **Sequence numbers** on every chunk (2 bytes)
- **Session ID** to multiplex multiple streams (2 bytes)
- **Checksum** per chunk (CRC16-CCITT)
- **ACK mechanism**: server acknowledges received upstream chunks via a field in downstream responses
- **Retransmission**: client retransmits unacknowledged chunks after timeout with exponential backoff (initial 500ms, max 10s, factor 1.5)
- **Reassembly buffer** on both sides — use a ring buffer with configurable size (default 64 slots)
- **Sliding window** (configurable, default 8) for concurrent in-flight queries
- **Duplicate detection**: track last N sequence numbers to silently drop duplicates

---

### 7. Concurrency & Speed
All concurrency via **libuv event loop** — single-threaded, async I/O:

- **Parallel queries**: send multiple DNS queries simultaneously (configurable window size)
- **Adaptive pipelining**: measure RTT and packet loss via EWMA, dynamically adjust window size (min 2, max 32)
- **Polling**: when server has downstream data for client but client hasn't sent a query, client sends periodic **poll queries** (empty data, just requesting pending downstream data)
- **Poll interval**: adaptive — fast when data is flowing (100ms), slow when idle (5s), with smooth ramp between them

```c
// Adaptive poll interval logic
if (bytes_received_recently > 0)
    poll_interval_ms = MAX(100, poll_interval_ms / 2);
else
    poll_interval_ms = MIN(5000, poll_interval_ms * 1.5);
```

---

### 8. Anti-Detection / Stealth
This is critical — the firewall uses DPI and traffic analysis:

- **Jitter**: add random delay (±20%) to query timing — use `getrandom()` or `/dev/urandom`, NOT `rand()`
- **Query type rotation**: periodically switch between working record types (every 30-120 queries, randomized)
- **Label length variation**: don't always max out label lengths — fill to random 70-100% capacity
- **Subdomain depth variation**: vary the number of labels (2-4 data labels per query)
- **Idle noise**: when tunnel is idle, occasionally send real-looking DNS queries to common domains mixed in with tunnel queries to maintain a natural traffic pattern. Use a built-in list of ~100 common domains
- **TTL mimicry**: when TTL steganography is in stealth mode, keep TTL values in realistic ranges (60-300s randomized)
- **Entropy management**: Base36 keeps entropy lower than Base64. Measure Shannon entropy of generated queries and warn if it exceeds threshold
- **Query volume throttling**: configurable max queries-per-second (default 50 qps). Use token bucket rate limiter
- **CNAME chain depth variation**: don't always use max chain depth — vary between 1 and max to avoid fixed patterns
- **Record count variation**: don't always return the same number of answer records — vary to look natural

---

### 9. Session & Handshake
- **Session init**: client sends a special "hello" query with a random 8-byte nonce encoded in the subdomain
- **Server responds** with session ID, supported record types, supported features (compression, EDNS0 size, working extra channels, max CNAME chain depth) encoded in the response
- **Keepalive**: periodic keepalive queries if no data flows for >30 seconds
- **Session resume**: if connection drops, client can resume with same session ID within a timeout window (default 120s)
- **Clean shutdown**: FIN flag in tunnel header for graceful teardown

---

### 10. SOCKS5 Proxy Interface
- Client exposes a **local SOCKS5 proxy** (default: `127.0.0.1:1080`)
- Implement SOCKS5 per RFC 1928:
  - Method negotiation (support NO AUTH only)
  - CONNECT command (TCP proxying)
  - IPv4 and domain name address types
- Each SOCKS5 connection maps to a **stream** within the DNS tunnel session
- Multiplex streams via session_id field in tunnel header
- Handle stream open/close/error cleanly

---

### 11. Health Check & Diagnostics
Build in a **`--check` mode** that runs at startup or on-demand:

```
$ ./dnstunnel-client --check --domain tunnel.yourdomain.com --resolver 10.0.0.1

=== DNS Record Type Support ===
[*] A record.......................... OK (4 B/resp)
[*] AAAA record....................... OK (16 B/resp)
[*] CNAME record...................... OK (~180 B/resp)
[*] MX record......................... OK (~180 B/resp)
[*] TXT record........................ BLOCKED (timeout)
[*] NULL record....................... BLOCKED (timeout)
[*] PTR record........................ OK (~180 B/resp)
[*] NAPTR record...................... OK (~500 B/resp)  ← BEST
[*] SRV record........................ OK (~260 B/resp)
[*] SOA record........................ OK (~526 B/resp)
[*] CAA record........................ OK (~253 B/resp)
[*] SVCB record (type 64)............ UNSUPPORTED
[*] HTTPS record (type 65)........... UNSUPPORTED
[*] HINFO record...................... OK (~510 B/resp)
[*] URI record (type 256)............. UNSUPPORTED

=== Extra Channel Support ===
[*] Transaction ID passthrough........ YES (+2 B/query)
[*] EDNS0 custom option (upstream).... YES (+variable)
[*] EDNS0 custom option (downstream).. NO (stripped)
[*] QCLASS non-standard.............. NO (query dropped)
[*] Authority section (NS names)...... YES (+~500 B/resp)
[*] Additional section (glue)......... YES (+~40 B/resp)
[*] TTL passthrough (unmodified)...... YES (+4 B/record)
[*] Multiple answer records........... YES (up to 15)

=== Bandwidth Multipliers ===
[*] CNAME chaining depth.............. max 4 hops (4x multiplier)
[*] NS referral chaining.............. max 2 hops (2x multiplier)
[*] EDNS0 max UDP size................ 4096 bytes

=== Performance ===
[*] RTT............................... avg 180ms, p99 340ms
[*] Packet loss....................... 2.1%
[*] Recommended window size........... 6

=== Summary ===
[*] Best record type: NAPTR (~500 B/resp)
[*] Extra channels: TXID + Authority + Additional + TTL
[*] Multiplier: CNAME chain x4
[*] Estimated bandwidth: ~25 KB/s up, ~120 KB/s down
[*] Config written to: recommended.conf
```

Also include:
- `--benchmark`: send test data back and forth, measure actual throughput for 10 seconds, test each record type individually and combined
- `--monitor`: live stats during operation printed to stderr every 5 seconds:
  ```
  [stats] up: 12.3 KB/s | down: 38.7 KB/s | rtt: 165ms | loss: 1.2% | qps: 47 | streams: 3 | type: NAPTR | chain: 3
  ```
- `--log-level debug|info|warn|error`
- `--check` should auto-generate a recommended config file based on test results

---

### 12. Server Component
The server runs as an **authoritative DNS server** for a zone you control (e.g., `tunnel.yourdomain.com`):

- Listens on UDP port 53 (and optionally TCP port 53 for large responses)
- Parses incoming queries for the tunnel zone
- Decodes upstream data from subdomain labels (and TXID, EDNS0 options if negotiated)
- Encodes downstream data into ALL working channels:
  - Answer section (record type data)
  - Authority section (NS names)
  - Additional section (glue records)
  - TTL fields (all records)
  - EDNS0 OPT options
- Implements CNAME chaining: when downstream buffer is large, respond with CNAME chain to trigger multiple recursive lookups
- Implements NS referral chaining: alternative to CNAME chains via delegation
- Maintains session state for connected clients (hash table keyed by session_id)
- Proxies TCP connections to their actual destinations (acts as the exit node)
- Forwards non-tunnel DNS queries to an upstream resolver (so the zone looks normal)
- Serves proper SOA and NS records for the tunnel zone
- Max clients configurable (default 100)
- Session cleanup: reap stale sessions every 60 seconds

---

### 13. Configuration
Use simple key=value config file format (no YAML/JSON dependency needed):

**Client config (`client.conf`):**
```ini
domain = tunnel.yourdomain.com
resolver = 10.0.0.1
listen = 127.0.0.1:1080
record_types = auto
edns0 = true
max_qps = 50
window_size = 8
compression = lz4
cname_chain = auto
ns_referral_chain = false
ttl_encoding = stealth
extra_channels = auto
log_level = info
```

**Server config (`server.conf`):**
```ini
domain = tunnel.yourdomain.com
listen = 0.0.0.0:53
upstream_dns = 8.8.8.8
max_clients = 100
session_timeout = 120
cname_chain_max = 4
ttl_encoding = stealth
log_level = info
```

All config values also overridable via command-line flags. Command-line takes priority over config file.

---

## Project Structure

```
dnstunnel/
├── CMakeLists.txt
├── README.md
├── client/
│   ├── main.c              # CLI parsing, config loading, entry point
│   ├── socks5.c/.h         # SOCKS5 proxy server
│   ├── tunnel_client.c/.h  # Client-side tunnel logic
│   └── check.c/.h          # --check, --benchmark, --monitor modes
├── server/
│   ├── main.c              # CLI parsing, config loading, entry point
│   ├── dns_server.c/.h     # DNS listener and responder
│   ├── tunnel_server.c/.h  # Server-side tunnel logic
│   ├── proxy.c/.h          # TCP proxy (exit node)
│   └── chain.c/.h          # CNAME chaining and NS referral logic
├── common/
│   ├── encode.c/.h         # Base36/Base32 encoding
│   ├── transport.c/.h      # Reliability layer (seq, ack, window)
│   ├── dns_packet.c/.h     # DNS packet helpers (wraps c-ares/ldns)
│   ├── channels.c/.h       # Multi-channel encoding (TXID, Authority, TTL, EDNS0, etc.)
│   ├── compress.c/.h       # LZ4 compression wrapper
│   ├── config.c/.h         # Config file parser
│   ├── log.c/.h            # Logging
│   ├── stealth.c/.h        # Jitter, noise, entropy management, rate limiting
│   └── util.c/.h           # Misc utilities, error handling
├── third_party/
│   ├── lz4.c               # Bundled LZ4
│   └── lz4.h
└── tests/
    ├── test_encode.c        # Encoding round-trip tests
    ├── test_transport.c     # Reliability layer tests
    ├── test_dns_packet.c    # Packet crafting/parsing tests
    ├── test_channels.c      # Multi-channel encode/decode tests
    ├── test_chain.c         # CNAME/NS chaining tests
    ├── test_integration.c   # Full client↔server test over loopback
    └── run_tests.sh         # Build + run all tests + ASan + Valgrind
```

---

## DNS Setup Instructions (include in README)
The user needs to:
1. Own a domain (e.g., `yourdomain.com`)
2. Create an NS record: `tunnel.yourdomain.com NS ns.yourdomain.com`
3. Create an A record: `ns.yourdomain.com A <server-ip>`
4. Run `dnstunnel-server` on `<server-ip>` port 53
5. Run `dnstunnel-client --check` first to test what works
6. Run `dnstunnel-client` with the recommended config
7. Configure browser/apps to use SOCKS5 proxy at `127.0.0.1:1080`

---

## Priority Order (Build Incrementally)
1. **Project skeleton**: CMakeLists.txt, directory structure, logging, config parser
2. **Encoding module**: Base36 encode/decode with round-trip tests
3. **DNS packet module**: craft queries, parse responses using c-ares/ldns, A record only
4. **Basic tunnel**: client sends data in subdomain → server decodes → server responds in A record → client decodes. Hardcoded, no reliability yet
5. **Reliability layer**: sequence numbers, ACKs, retransmission, CRC16, ring buffer. With tests
6. **SOCKS5 proxy**: local listener, CONNECT command, stream multiplexing
7. **libuv integration**: async event loop, parallel queries, adaptive polling
8. **Multi-record types**: AAAA, CNAME, NAPTR, SRV, SOA, CAA, HINFO — auto-detection and fallback
9. **Multi-channel encoding**: TXID, Authority section, Additional section, TTL, EDNS0 options — with channel negotiation
10. **CNAME chaining**: chain logic on server, chain parsing on client, depth probing
11. **NS referral chaining**: delegation-based multiplier as alternative to CNAME
12. **Stealth features**: jitter, type rotation, label variation, idle noise, TTL mimicry, entropy monitoring
13. **Diagnostics**: `--check` (full probe of all types + channels + chains), `--benchmark`, `--monitor`
14. **Compression**: LZ4 integration, negotiation
15. **EDNS0**: probe and enable large responses
16. **Remaining record types**: MX, TXT, NULL, PTR, SVCB, HTTPS, URI
17. **Cross-compilation**: musl static builds, ARM64
18. **Integration tests**: full end-to-end over loopback with data integrity verification
19. **README**: complete setup guide, DNS configuration, usage examples, troubleshooting, cross-compile instructions
