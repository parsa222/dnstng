# STmemory.md — DnstTNG Session State

For the next agent picking this up. Read LTMemory.MD for the full original spec.

---

## What Was Implemented This Session

### New Files Created

| File | What It Does |
|------|-------------|
| `common/channel.h/.c` | Multi-channel pack/unpack. Encodes a binary payload across NAPTR, SOA, CAA, SRV, Auth NS names, Additional A records, EDNS0 option 65001, and TTL steganography (lower 24 bits per record). 3-byte fragment header [offset_hi, offset_lo, frag_len] on each record allows reassembly on the client side. ~730 lines. |
| `server/chain.h/.c` | CNAME chaining (`chain_build_cname` / `chain_parse_cname`) and NS referral chaining (`chain_build_ns_referral` / `chain_parse_ns_referral`). CNAME targets use format `{base36}.c{i}.t.{domain}`. NS names use `{base36}.ns{i}.{domain}`. Max depth 8. ~413 lines. |
| `common/smtp_channel.h/.c` | SMTP backup tunnel over libuv TCP. Upstream: `EHLO {base36}.t.{domain}`. Downstream: `250-{base36}` continuation lines. ~220 lines. |
| `common/ocsp_channel.h/.c` | OCSP covert channel over HTTP. Upstream: `GET /ocsp/{base36}`. Downstream: `X-Tunnel-Data: {hex}` header. ~235 lines. |
| `common/crl_channel.h/.c` | CRL covert channel over HTTP. Upstream: `GET /crl/{seq}/{base36}.crl`. Downstream: `X-Tunnel-Data: {hex}` header. ~232 lines. |
| `tests/test_channel.c` | Round-trip tests for channel_pack / channel_unpack across NAPTR, CAA, Additional A, and fragment reassembly. Passes. |
| `tests/test_chain.c` | Round-trip tests for CNAME chain build/parse and NS referral build/parse. Passes. |
| `LTMemory.MD` | Full original spec file (was on main branch, pulled into working branch). |

### Modified Files

| File | What Changed |
|------|-------------|
| `common/dns_packet.h` | Added 10 new `CHAN_*` flags (CHAN_NAPTR, CHAN_SRV, CHAN_CAA, CHAN_SOA_DATA, CHAN_SVCB_DATA, CHAN_CNAME_CHAIN, CHAN_NS_CHAIN, CHAN_SMTP, CHAN_OCSP, CHAN_CRL). Added `CHAN_ALL_DNS` and `CHAN_ALL_BACKUP` convenience masks. Added `dns_build_svcb_rdata()` and `dns_build_hinfo_rdata()` declarations. |
| `common/dns_packet.c` | Implemented `dns_build_svcb_rdata()` (priority + target name + raw params) and `dns_build_hinfo_rdata()` (CPU + OS length-prefixed strings). |
| `common/config.h` | Added to `client_config_t`: `active_channels`, `cname_chain_depth`, `ns_chain_depth`, `ttl_encoding`, `smtp_host/port`, `ocsp_host/port`, `crl_host/port`. Added same channel/chain fields to `server_config_t`. |
| `common/config.c` | Defaults: `active_channels = CHAN_ALL_DNS`, `cname_chain_depth = 3`, `ns_chain_depth = 2`, `ttl_encoding = 1` (stealth). Parses all new keys in client_kv/server_kv. |
| `CMakeLists.txt` | Added all new `.c` files to `common_lib` via `file(GLOB)`. Added `server/chain.c` to `dnstunnel-server`. Added `test_channel` and `test_chain` test targets. |
| `README.md` | Replaced the 2-line placeholder with full DnstTNG documentation (~320 lines, sarcastic tone, no emojis). Covers: architecture, all DNS channels, backup channels, setup, build, config reference, bandwidth estimates. |

### Build and Test Status

- Build: CLEAN (zero warnings, zero errors, `-Wall -Wextra -Werror -pedantic`)
- Tests: 5/5 PASS (test_encode, test_transport, test_dns_packet, test_channel, test_chain)

---

## What Is NOT Done (TODO for Next Agent)

### Critical — Not Wired Up

The new channel and chain code is implemented and tested in isolation but NOT yet integrated
into the live tunnel data path. The server still responds with a plain TXT record. The client
still only parses TXT/NULL records from responses.

Specific integration work needed:

1. **`server/tunnel_server.c` — use `channel_pack()`**
   - In `on_dns_query()`, after building the ACK transport packet, call `channel_buf_init()` +
     `channel_pack()` instead of the current `encode_to_labels()` + `dns_server_respond()`.
   - Use `dns_build_response_ext()` to send the multi-channel response.
   - Check `sess->transport.active_channels` to know which channels are negotiated.

2. **`server/tunnel_server.c` — use chain when channel includes CHAN_CNAME_CHAIN**
   - If `active_channels & CHAN_CNAME_CHAIN`, call `chain_build_cname()` instead of the
     standard response builder. Depth from `ts->cfg.cname_chain_depth`.
   - If `active_channels & CHAN_NS_CHAIN`, call `chain_build_ns_referral()`.

3. **`client/tunnel_client.c` — use `channel_unpack()`**
   - In `ares_txt_cb()`, instead of only parsing TXT/NULL records, call
     `dns_parse_response_full()` to get a `dns_parsed_response_t`, then call
     `channel_unpack()` to extract all channel data into a flat buffer.
   - Feed the flat buffer into `transport_parse_packet()`.

4. **`client/tunnel_client.c` — parse CNAME chains**
   - When the response contains CNAME records (type 5), call `chain_parse_cname()`.
   - When response has NS records in authority, call `chain_parse_ns_referral()`.

5. **`server/dns_server.h/.c` — add `dns_server_respond_ext()`**
   - Current `dns_server_respond()` only takes raw `(data, len)` and always builds a TXT record.
   - Need a new function that takes a `dns_response_ext_t *` and calls `dns_build_response_ext()`.
   - Or: change the existing respond function to accept a pre-built packet buffer.

6. **Channel negotiation handshake**
   - Currently `transport_ctx_t.active_channels` is never set during a real session.
   - The SYN exchange should negotiate which channels work (client sends probe, server replies
     with bitmask of supported channels, both sides store in session state).
   - The `--check` mode in `client/check.c` already tests channels but does not write the
     result back into the config for use during the session.

### Important — Missing Features from LTMemory.MD Spec

7. **Adaptive window size** (LTMemory spec section 7)
   - Window size is fixed at `WINDOW_SIZE_DEFAULT = 8`.
   - Spec requires EWMA-based RTT measurement and dynamic window adjustment (min 2, max 32).

8. **Adaptive poll interval** (LTMemory spec section 7)
   - Poll timer is fixed at 50ms. Spec requires ramping from 100ms (active) to 5s (idle).

9. **`--monitor` mode** (LTMemory spec section 11)
   - Spec requires live stats printed to stderr every 5 seconds:
     `[stats] up: X KB/s | down: X KB/s | rtt: Xms | loss: X% | qps: X | streams: X | type: X`
   - Not yet implemented in `client/check.c`.

10. **Query type rotation / stealth rotation** (LTMemory spec section 8)
    - The tunnel always queries with TXT type. Spec requires rotating between working record
      types every 30-120 queries (randomized interval). Not implemented.

11. **Label length / subdomain depth variation** (LTMemory spec section 8)
    - Queries always use maximum label fill. Spec requires varying to 70-100% capacity and
      varying number of labels (2-4) to avoid fingerprinting.

12. **Token-bucket rate limiter** (LTMemory spec section 8)
    - Spec requires configurable max queries-per-second (default 50 qps). Not implemented.

13. **EDNS0 size probing** (LTMemory spec section 4)
    - `--check` currently only tests 4096 byte EDNS0. Spec requires probing 4096, 2048, 1232,
      512 to find the max that works end-to-end.

14. **QCLASS non-standard probing** (LTMemory spec section 2)
    - Spec requires testing whether setting QCLASS to CH (3) or HS (4) still gets forwarded.
      Not tested in `--check`.

15. **Session resume** (LTMemory spec section 9)
    - Spec requires that if connection drops, client can resume with same session ID within
      a timeout window (default 120s). Sessions are currently not resumable.

16. **Integration test** (LTMemory spec section 18)
    - `tests/test_integration.c` does not exist yet. Spec requires a full client-server
      loopback test with data integrity verification.

17. **Cross-compilation toolchain files** (LTMemory spec section, Build)
    - No `cmake/` directory with toolchain files for aarch64 or musl static builds.

18. **Backup channel integration into session fallback**
    - `smtp_channel`, `ocsp_channel`, `crl_channel` are implemented as standalone modules
      but are not connected to the tunnel client's session logic. When DNS fails (consecutive
      timeouts exceeding a threshold), the client should automatically fall back to the first
      available backup channel. Not wired up.

19. **HINFO and URI record types**
    - `dns_build_hinfo_rdata()` is implemented. URI (type 256) is in the spec's table but has
      no RDATA builder yet. Neither is used as an active channel in `channel.c`.

20. **Multiple answer records for A/AAAA queries**
    - Spec says return 10+ A records per response for A-type queries. Currently only 1 answer
      record is returned regardless of type.

---

## Future Update Ideas

These are beyond the current spec but worth considering for a v2:

- **TCP DNS fallback:** When UDP responses exceed 512 bytes and EDNS0 is stripped, the DNS
  protocol allows falling back to TCP port 53. Implementing DNS-over-TCP as a transport would
  remove the size limitation entirely.

- **DoH (DNS-over-HTTPS) transport:** Instead of raw UDP DNS, send queries as HTTPS POST
  requests to a DoH endpoint. Traffic looks identical to browser DNS-over-HTTPS. Requires
  a TLS library (OpenSSL / mbedTLS). This would be its own parallel transport module.

- **DoT (DNS-over-TLS) transport:** Similar to DoH but uses TLS-wrapped DNS on port 853.
  Many networks whitelist this port explicitly for DNS resolution.

- **Padding and traffic shaping:** EDNS0 PADDING option (RFC 7830) can be used to pad all
  queries to fixed sizes, preventing traffic analysis based on query size patterns.

- **Multi-server failover:** Client config could list multiple tunnel servers. On timeout,
  rotate to the next server automatically. Useful when one server's IP gets blocked.

- **Asymmetric channel split:** Use a high-bandwidth type (NAPTR/SOA) for downstream and
  a different type (A) for upstream probes, tuned independently.

- **Compression negotiation per session:** Currently LZ4 is available but not auto-enabled.
  The SYN handshake should negotiate compression support and enable it when both sides agree.

- **DNSSEC-aware mode:** If the network validates DNSSEC, forged responses from our
  authoritative server will be rejected unless we also sign them. Adding DNSSEC signing
  to the server would make this work in DNSSEC-enforcing environments.

- **Web UI / stats dashboard:** A minimal HTTP server (using libuv) serving a stats page
  at `127.0.0.1:8080` during tunnel operation. Easier to read than log output.

- **Android / iOS client app:** The tunnel client is a SOCKS5 proxy. Wrapping it in a
  minimal Android app (using the NDK) would make it usable without a terminal.

---

## Architecture Notes for Next Agent

- All channel code lives in `common/` and is shared between client and server.
- The `channel_buf_t` struct is stack-allocated (it is ~100KB due to the rdata scratch buffer —
  consider heap-allocating it or reducing `CHANNEL_RDATA_CAP` if stack size is a concern).
- `server/chain.c` only contains build/parse functions. It has no state and no libuv dependency.
  The actual decision of when to use chaining belongs in `server/tunnel_server.c`.
- The backup channel structs (`smtp_channel_t`, `ocsp_channel_t`, `crl_channel_t`) each
  embed a `uv_tcp_t` directly. This means they must not be moved in memory after `_connect()`
  is called (libuv requirement). Allocate them with malloc if they need to live on the heap.
- The 3-byte fragment header format (offset_hi, offset_lo, frag_len) is the contract between
  `channel_pack()` and `channel_unpack()`. Do not change it without updating both sides.
- `dns_parsed_response_t` (from `dns_packet.h`) holds up to 128 RRs. If more records are
  returned (e.g., 10 A records + 4 NAPTR + 4 NS + 4 glue = 22 records), this is fine.
  128 is a safe upper bound for realistic DNS responses.
