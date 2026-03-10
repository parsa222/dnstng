# TODO.md — DnstTNG Task List

Priority 1 items are **DONE** — the tunnel data path is wired end-to-end.
Priority 2 items are required by the spec (`LTMemory.MD`) but not yet implemented.
Priority 3 items are future ideas beyond the current spec.

---

## Priority 1 — Critical Integration ✅ COMPLETE

All six integration tasks are done. The server responds with multi-channel packed
DNS responses (NAPTR, CAA, SOA, SRV, Auth NS, Additional, EDNS0, TTL steganography,
CNAME chain, NS referral). The client unpacks them using `channel_unpack()` and
`chain_parse_*()`. Channel negotiation happens in the SYN/SYN-ACK handshake
(4-byte bitmask payload). The `dns_server_send_raw()` API sends pre-built DNS packets.
An end-to-end integration test (`tests/test_integration.c`) covers all of these paths.

Domain convention: the default tunnel domain is `example.com` (single subdomain).
FQDNs look like `{data}.{session}.t.example.com`.

- [x] **1. Wire `channel_pack()` into `server/tunnel_server.c`**
- [x] **2. Wire CNAME/NS chaining into `server/tunnel_server.c`**
- [x] **3. Wire `channel_unpack()` into `client/tunnel_client.c`**
- [x] **4. Wire CNAME/NS chain parsing into `client/tunnel_client.c`**
- [x] **5. Add `dns_server_send_raw()` to `server/dns_server.c`**
- [x] **6. Implement channel negotiation in the SYN handshake**

---

## Priority 2 — Spec-Required Features (`LTMemory.MD`)

These are required by the original spec but not yet implemented.

### 7. Adaptive window size (`LTMemory` §7)

Window size is currently fixed at `WINDOW_SIZE_DEFAULT = 8` (`transport.h`).
Spec requires EWMA-based RTT measurement and dynamic adjustment (min 2, max 32).
- Track RTT per query (timestamp at send, timestamp at receive ack).
- Compute EWMA: `rtt_ewma = 0.875 * rtt_ewma + 0.125 * sample`.
- Adjust window: increase by 1 if RTT improved; decrease by 1 if RTT degraded; clamp 2-32.

### 8. Adaptive poll interval (`LTMemory` §7)

Poll timer is fixed at 50ms. Spec: ramp from 100ms (active traffic) to 5s (idle).
- "Active" = data was received in the last poll cycle.
- "Idle" = no data received; double the interval each cycle up to 5000ms.
- Reset to 100ms on any received data.

### 9. `--monitor` mode (`LTMemory` §11)

Print live stats to stderr every 5 seconds during tunnel operation:
```
[stats] up: X KB/s | down: X KB/s | rtt: Xms | loss: X% | qps: X | streams: X | type: X
```
Add to `client/check.c` as a `--monitor` flag that attaches to a running session.

### 10. Query type rotation (`LTMemory` §8)

The tunnel always queries with TXT type. Spec: rotate between working record types
every 30-120 queries (randomized interval) to avoid fixed traffic patterns.
- Maintain a list of `active_record_types[]` from the `--check` result.
- After every N queries (N = random in [30, 120]), pick the next type in the list.

### 11. Label length / subdomain depth variation (`LTMemory` §8)

Queries always use maximum label fill. Spec: vary fill to 70-100% and vary label
count (2-4 labels) to avoid fingerprinting. Add to `stealth.c` as a helper that
chooses fill and depth for a given query, controlled by `getrandom()`.

### 12. Token-bucket rate limiter (`LTMemory` §8)

Spec: configurable max queries-per-second, default 50 qps. Add a token bucket in
`client/tunnel_client.c`. Add `max_qps` to `client_config_t`.

### 13. EDNS0 size probing (`LTMemory` §4)

`--check` currently tests only one EDNS0 size (4096). Spec: probe 4096, 2048, 1232, 512
and find the largest that survives end-to-end. Store result in `channel_caps_t`.

### 14. QCLASS probing (`LTMemory` §2)

Spec: test whether setting QCLASS to CH (3) or HS (4) gets forwarded by the resolver.
Add to `--check` output.

### 15. Session resume (`LTMemory` §9)

Spec: if connection drops, client can resume with the same session ID within a timeout
window (default 120s). Server must hold session state for 120s after last query.
- Add `last_seen_ms` to the server session struct.
- On SYN with an existing `session_id`, resume rather than creating a new session.

### 16. Integration test ✅ DONE

`tests/test_integration.c` is implemented with 7 sub-tests covering the full pipeline:
SYN handshake with channel negotiation, data round-trip through multi-channel, CNAME chain,
NS referral chain, upstream/downstream FQDN encoding, all channels combined, and config
defaults verification.

### 17. Cross-compilation toolchain files

Create `cmake/aarch64-linux-gnu.cmake` and `cmake/x86_64-linux-musl.cmake`.
The README's cross-compilation section references these files but they don't exist.

### 18. Backup channel fallback in client session logic

`smtp_channel`, `ocsp_channel`, `crl_channel` are standalone tested modules but are not
connected to the client's session. When DNS fails (e.g., 5 consecutive timeouts), the
client should:
1. Try SMTP channel (if `cfg.smtp_host` is set).
2. On SMTP failure, try OCSP channel (if `cfg.ocsp_host` is set).
3. On OCSP failure, try CRL channel (if `cfg.crl_host` is set).
4. Set `sess->transport.active_channels` to the backup channel flag and resume.

### 19. URI record type and HINFO channel activation

`dns_build_hinfo_rdata()` is implemented in `dns_packet.c` but HINFO is not an active
channel in `channel.c`. URI (type 256) is in the spec table but has no RDATA builder.
- Add `CHAN_HINFO` flag and wire it into `channel_pack/unpack`.
- Add `dns_build_uri_rdata()` and a `CHAN_URI` flag.

### 20. Multiple A/AAAA records per response

Spec: return 10+ A records per response for A-type queries. Currently only 1 answer
record is returned. Update `channel_pack()` and `dns_build_response_ext()` to fill
as many A/AAAA records as the downstream data requires.

---

## Priority 3 — Future Ideas (Beyond Current Spec)

These are not in `LTMemory.MD` but worth doing for v2.

- **TCP DNS fallback:** When UDP exceeds 512 bytes and EDNS0 is stripped, fall back to
  DNS-over-TCP (port 53) to remove the size ceiling entirely.

- **DoH transport:** Send queries as HTTPS POST to a DoH endpoint. Traffic looks like
  browser DoH. Requires a TLS library (mbedTLS preferred for static linking).

- **DoT transport:** TLS-wrapped DNS on port 853. Many networks whitelist this port for DNS.

- **EDNS0 PADDING (RFC 7830):** Pad all queries to fixed sizes to defeat traffic analysis
  based on query size patterns.

- **Multi-server failover:** List multiple server IPs in config; rotate on timeout.

- **Compression negotiation:** Currently LZ4 is available but not auto-enabled. The SYN
  handshake should negotiate compression support.

- **DNSSEC-aware mode:** Sign server responses so the tunnel works in DNSSEC-enforcing networks.

- **Web stats dashboard:** Minimal HTTP server (libuv) at `127.0.0.1:8080` during operation.

- **Android/iOS client:** Wrap the SOCKS5 client in a minimal Android NDK app.
