# ARCHITECTURE.md — DnstTNG Technical Architecture

This document describes the internal architecture of DnstTNG. Read this before modifying
`tunnel_server.c`, `tunnel_client.c`, `channel.c`, or `transport.c`.

---

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  CENSORED NETWORK                                                   │
│                                                                     │
│  [Local App] ──SOCKS5──► [dnstunnel-client]                        │
│                                   │                                 │
│                    DNS query (UDP/53) to domestic resolver          │
│                                   │                                 │
│              [Domestic Recursive Resolver]  ◄── whitelisted         │
│                                   │                                 │
│                     recursive lookup (outside)                      │
└───────────────────────────────────┼─────────────────────────────────┘
                                    │
┌───────────────────────────────────▼─────────────────────────────────┐
│  OUTSIDE NETWORK                                                     │
│                                                                      │
│              [dnstunnel-server]  (authoritative NS)                  │
│                   │                                                   │
│                   └──TCP──► [Target Server on the internet]          │
└──────────────────────────────────────────────────────────────────────┘
```

The client is behind a firewall that permits DNS but blocks everything else.
The client speaks to a domestic resolver it cannot control or inspect.
The domestic resolver speaks to the server's authoritative nameserver on the client's behalf.

---

## Component Breakdown

### `common/` — Shared Protocol Library

Built as `common_lib` (static library). Used by both binaries.

#### `transport.c` — Reliability Layer

DNS is UDP. This layer adds reliability on top:

```
tunnel_header_t (6 bytes, packed):
  session_id  uint16  identifies the session this packet belongs to
  seq_num     uint16  sequence number of this packet
  ack_num     uint16  highest seq the sender has received from the other side
  checksum    uint16  CRC16-CCITT over the entire packet
  flags       uint8   SYN | ACK | FIN | DATA | POLL
  payload_len uint8   number of payload bytes following the header
```

`transport_ctx_t` holds a 64-slot ring buffer (`ring_slot_t[64]`) for retransmission.
The sliding window is `WINDOW_SIZE_DEFAULT = 8` concurrent in-flight queries (TODO: make
this adaptive; see `TODO.md` §7).

Retransmission: exponential backoff, initial 500ms, max 10s, factor 1.5.

#### `dns_packet.c` — DNS Wire Format

Two build paths:
- `dns_build_response()` — simple: answer section with a list of `dns_answer_t` records.
- `dns_build_response_ext()` — full: answer + authority NS + additional glue + EDNS0 option.
  Takes a `dns_response_ext_t *` struct.

Two parse paths:
- `dns_parse_response()` — simple callback-based, answer section only.
- `dns_parse_response_full()` — full: all three sections, EDNS0 option, TXID.
  Fills a `dns_parsed_response_t` (128 RRs max).

RDATA builders: `dns_build_naptr_rdata`, `dns_build_srv_rdata`, `dns_build_caa_rdata`,
`dns_build_soa_rdata`, `dns_build_svcb_rdata`, `dns_build_hinfo_rdata`.

#### `channel.c` — Multi-Channel Pack/Unpack

This is the core differentiator. One `channel_pack()` call turns a binary payload into a
fully-populated `dns_response_ext_t` that uses every negotiated channel simultaneously.

**Fragment protocol:** Every rdata payload (in every record, in every section) starts with
a 3-byte header:
```
byte 0-1: data_offset (uint16 big-endian) — position in the full stream
byte 2:   fragment_len (uint8) — data bytes in this fragment
```
`channel_unpack()` collects all fragments from all channels in all sections of a response
and reassembles them into a flat buffer, sorted by `data_offset`.

**Channel priority order** (how `channel_pack` fills channels):
1. NAPTR records (RDATA Regexp + Replacement fields, ~500 bytes each)
2. SOA record (MNAME/RNAME labels + 5 numeric fields, ~526 bytes)
3. CAA records (~253 bytes each)
4. SRV records (~260 bytes each)
5. Auth NS names (base36 labels in NS name, ~200 bytes each, 8 slots)
6. Additional glue A/AAAA records (raw IP bytes)
7. EDNS0 option 65001 (variable, pass-through dependent)
8. TTL steganography (3 bytes per record across all sections)

**`channel_buf_t`** is stack-allocated (~100KB due to the 8192-byte rdata scratch buffer).
The `cb->resp` field holds raw pointers into the arrays in `cb` — do not move after init.

#### `server/chain.c` — CNAME and NS Referral Chaining

Bandwidth multiplier: one client query triggers multiple server responses.

CNAME chain format:
```
{base36_data_chunk}.c{i}.t.{domain}
```
Each CNAME record's target name encodes a data chunk in its labels.
The resolver follows the chain; each link is another server response.
Default depth 3, max 8.

NS referral chain format:
```
{base36_data_chunk}.ns{i}.{domain}
```
NS records in the authority section. The resolver follows the delegation.
More stealthy than CNAME chains; less reliable due to resolver caching.

Both build and parse functions are in `server/chain.c` (despite the path, the parse
functions are also needed by the client — consider moving to `common/` in a refactor).

#### Backup Channels

All three use libuv TCP. Each has `_connect()`, `_send()`, `_recv()`, `_close()` functions.

| Module | Protocol | Upstream encoding | Downstream encoding |
|--------|----------|-------------------|---------------------|
| `smtp_channel.c` | SMTP port 25/587 | `EHLO {base36}.t.{domain}` | `250-{base36}` lines |
| `ocsp_channel.c` | HTTP port 80 | `GET /ocsp/{base36}` | `X-Tunnel-Data: {hex}` header |
| `crl_channel.c`  | HTTP port 80 | `GET /crl/{seq}/{base36}.crl` | `X-Tunnel-Data: {hex}` header |

**Note:** These are currently not connected to the session logic. See `TODO.md` §18.

---

### `client/` — Client Binary

```
main.c
  └─ Parses CLI, loads client_config_t, creates uv_loop, starts socks5_server + tunnel_client

socks5.c
  └─ Listens on 127.0.0.1:1080 (configurable)
  └─ RFC 1928 SOCKS5: accepts CONNECT requests
  └─ Each accepted stream creates a new tunnel stream, calls into tunnel_client

tunnel_client.c
  └─ Manages per-session transport_ctx_t
  └─ Sends DNS queries via c-ares (using the configured resolver IP)
  └─ Currently: encodes upstream data as base36 subdomain labels, queries TXT type
  └─ TODO: negotiate channels on SYN, use channel_unpack on responses

check.c
  └─ --check: probes each DNS record type and secondary channel
  └─ Prints channel_caps_t result
  └─ TODO: write result into client_config_t.active_channels for use in session SYN
```

#### Client Data Flow (current, incomplete)

```
TCP stream from SOCKS5
  → split into TUNNEL_MAX_PAYLOAD (200 byte) chunks
  → transport_build_packet() adds 6-byte header + CRC
  → base36-encode the packet bytes
  → encode as subdomain labels: {base36}.{session_hex}.t.{domain}
  → c-ares DNS query (TXT type) to configured resolver
  → response: parse TXT RDATA only
  → transport_parse_packet() strips header
  → reassemble and deliver to TCP stream
```

#### Client Data Flow (target, after TODO §1-6)

```
TCP stream from SOCKS5
  → transport_build_packet()
  → base36-encode upstream payload into subdomain labels
  → optionally: embed extra bytes in TXID (CHAN_TXID) and EDNS0 option (CHAN_EDNS_OPT)
  → c-ares DNS query (negotiated record type, rotated per TODO §10)
  → response: dns_parse_response_full()
  → channel_unpack() extracts all fragments from all channels
  → if CNAME chain: chain_parse_cname() for each chain link
  → if NS referral: chain_parse_ns_referral()
  → reassemble flat buffer
  → transport_parse_packet()
  → deliver to TCP stream
```

---

### `server/` — Server Binary

```
main.c
  └─ Parses CLI, loads server_config_t, creates uv_loop, starts dns_server + tunnel_server

dns_server.c
  └─ UDP listener on 0.0.0.0:53 (configurable)
  └─ Reads incoming DNS packets, calls tunnel_server_on_query() for tunnel domain queries
  └─ Passes non-tunnel queries upstream to configured DNS resolver
  └─ TODO: add dns_server_send_raw() for pre-built packet buffers (TODO §5)

tunnel_server.c
  └─ Per-session state: session_id → transport_ctx_t + TCP proxy stream
  └─ on_dns_query(): decodes upstream data from query labels, builds response
  └─ Currently: responds with plain TXT record
  └─ TODO: use channel_pack() + dns_build_response_ext() (TODO §1, §2)

chain.c
  └─ chain_build_cname() / chain_parse_cname()
  └─ chain_build_ns_referral() / chain_parse_ns_referral()
  └─ No state, no libuv dependency. Pure build/parse functions.

proxy.c
  └─ TCP proxy: connects to the target address from the SOCKS5 CONNECT request
  └─ Shuttles bytes between the TCP connection and the tunnel session
```

#### Server Data Flow (current, incomplete)

```
Incoming DNS query (UDP)
  → dns_server.c: detect tunnel domain suffix
  → tunnel_server.c: decode base36 subdomain labels → transport packet
  → transport_parse_packet(): extract session_id, flags, payload
  → session lookup / creation
  → payload → TCP proxy → target server
  → response from target → transport_build_packet()
  → encode as TXT record, dns_build_response()
  → send UDP response
```

#### Server Data Flow (target, after TODO §1-6)

```
Incoming DNS query (UDP)
  → decode base36 subdomain labels
  → additionally extract upstream bytes from TXID and EDNS0 option 65001
  → transport_parse_packet()
  → session lookup / creation (with resume if SYN contains existing session_id; TODO §15)
  → payload → TCP proxy
  → response from proxy → transport_build_packet()
  → channel_buf_init() + channel_pack(): fill all negotiated channels
  → if CHAN_CNAME_CHAIN: chain_build_cname()
  → if CHAN_NS_CHAIN: chain_build_ns_referral()
  → dns_build_response_ext() → raw packet buffer
  → dns_server_send_raw() → UDP response
```

---

## Upstream Encoding (Client → Server)

Data travels in the subdomain labels of the query FQDN:

```
{base36_payload}.{session_id_hex}.t.{tunnel_domain}
e.g.: 3x9kp2r.0042.t.tunnel.example.com
```

- **Base36** (0-9, a-z): lower entropy than base32 or base64; looks like a plausible subdomain.
- Each label: max 63 characters (DNS limit).
- Total FQDN: max 253 characters (DNS limit).
- Additional upstream bytes via TXID (2 bytes) and EDNS0 option 65001 (variable, if preserved).

## Downstream Encoding (Server → Client)

Data travels across multiple fields simultaneously. Total downstream capacity per response
depends on which channels were negotiated:

| Channel | Typical capacity | CHAN_* flag |
|---------|-----------------|-------------|
| NAPTR records (multiple) | ~500 bytes each | `CHAN_NAPTR` |
| SOA record | ~526 bytes | `CHAN_SOA_DATA` |
| CAA records | ~253 bytes each | `CHAN_CAA` |
| SRV records | ~260 bytes each | `CHAN_SRV` |
| Authority NS names | ~200 bytes × 8 | `CHAN_AUTH_NS` |
| Additional glue A/AAAA | 4-16 bytes × N | `CHAN_ADDL_GLUE` |
| EDNS0 option 65001 | variable | `CHAN_EDNS_OPT` |
| TTL steganography | 3 bytes × all RRs | `CHAN_TTL_DATA` |
| CNAME chain (multiplier) | repeats above × depth | `CHAN_CNAME_CHAIN` |
| NS referral chain | repeats above × depth | `CHAN_NS_CHAIN` |

---

## Error Handling

All functions return `err_t` (from `util.h`) or a positive integer byte count (negative = error).

```c
typedef enum {
    ERR_OK       =  0,
    ERR_NOMEM    = -1,
    ERR_INVAL    = -2,
    ERR_OVERFLOW = -3,
    ERR_IO       = -4,
    ERR_TIMEOUT  = -5,
    ERR_NOTFOUND = -6,
    ERR_PROTO    = -7,
} err_t;
```

Every call site must check the return value. Never ignore.

---

## Dependency Graph

```
dnstunnel-client
  ├── client/main.c
  ├── client/socks5.c
  ├── client/tunnel_client.c
  ├── client/check.c
  └── common_lib
        ├── dns_packet.c   (no external deps beyond libc)
        ├── channel.c      (depends on dns_packet)
        ├── transport.c    (depends on util)
        ├── encode.c       (no deps)
        ├── compress.c     (depends on third_party/lz4)
        ├── config.c       (depends on encode, log, dns_packet)
        ├── smtp_channel.c (depends on libuv, encode)
        ├── ocsp_channel.c (depends on libuv, encode)
        ├── crl_channel.c  (depends on libuv, encode)
        ├── stealth.c      (depends on encode)
        ├── log.c          (no deps)
        └── util.c         (no deps)

dnstunnel-server
  ├── server/main.c
  ├── server/dns_server.c  (depends on libuv, dns_packet)
  ├── server/tunnel_server.c
  ├── server/chain.c       (depends on encode, dns_packet)
  ├── server/proxy.c       (depends on libuv)
  └── common_lib           (same as above)

External dependencies:
  libuv     — async I/O event loop
  c-ares    — DNS client (client binary only)
  lz4       — bundled as third_party/lz4.c
```

---

## Memory Ownership Rules

- **`transport_ctx_t`**: caller owns; call `transport_free()` before freeing the struct.
- **`channel_buf_t`**: stack-allocated by the caller before each pack/unpack call. No cleanup needed.
- **`dns_parsed_response_t`**: stack-allocated by the caller of `dns_parse_response_full()`. No cleanup.
- **`smtp_channel_t` / `ocsp_channel_t` / `crl_channel_t`**: must be heap-allocated (malloc).
  Call `_close()` before free, and only free after the libuv close callback fires.
- **`client_config_t` / `server_config_t`**: stack-allocated in `main.c`. Passed by pointer everywhere.

---

## Test Coverage

| Test file | What it covers |
|-----------|----------------|
| `test_encode.c` | Base36/Base32 round-trips, edge cases (empty, max length) |
| `test_transport.c` | Header build/parse, checksum, retransmit logic, ring buffer |
| `test_dns_packet.c` | Query build, response build, RDATA builders, full parser |
| `test_channel.c` | `channel_pack` / `channel_unpack` round-trips, fragment reassembly |
| `test_chain.c` | CNAME chain build/parse, NS referral build/parse, depth limits |

There is no integration test yet (`TODO.md` §16).
