# TODO.md — DnstTNG Task List

Priority 1 items are **DONE** — the tunnel data path is wired end-to-end.
Priority 2 items are marked with
Priority 3 items are future ideas beyond the current spec.

---

## Priority 1 — Critical Integration 

All six integration tasks are done. The server responds with mu  i-channel packed
DNS responses (NAPTR, CAA, SOA, SRV, Auth NS, Additional, EDNS0, TTL steganography,
CNAME chain, NS referral). The client unpacks them using `channel_unpack()` and
`chain_parse_*()`. Channel negotiation happens in the SYN/SYN-ACK handshake
(4-byte bitmask payload). The `dns_server_send_raw()` API sends pre-bui   DNS packets.
An end-to-end integration test (`tests/test_integration.c`) covers all of these paths.

Domain convention: the defau   tunnel domain is `example.com` (single subdomain).
FQDNs look like `{data}.{session}.t.example.com`.

- [x] **1. Wire `channel_pack()` into `server/tunnel_server.c`**
- [x] **2. Wire CNAME/NS chaining into `server/tunnel_server.c`**
- [x] **3. Wire `channel_unpack()` into `client/tunnel_client.c`**
- [x] **4. Wire CNAME/NS chain parsing into `client/tunnel_client.c`**
- [x] **5. Add `dns_server_send_raw()` to `server/dns_server.c`**
- [x] **6. Implement channel negotiation in the SYN handshake**

---

### 7. Adaptive window size (`   ` §7) 

EWMA-based RTT measurement and dynamic window adjustment (min 2, max 32).
Implemented in `common/transport.c` via `transport_update_rtt()`.
- EWMA: `rtt_ewma = 0.875 * rtt_ewma + 0.125 * sample`.
- Window grows by 1 when RTT improves, shrinks by 1 when RTT degrades >25%.
- Tested in `test_integration.c::test_adaptive_window`.

### 8. Adaptive poll interval (`   ` §7) 

Ramps from 100ms (active traffic) to 4s (idle), iodine-inspired.
Implemented in `client/tunnel_client.c` via `poll_timer_cb()`.
- POLL_MIN_MS=100, POLL_MAX_MS=4000, POLL_RAMP_STEP=50
- Idle: interval increases by 50ms per idle poll until 4s max.
- Data flowing: interval resets to 100ms immediately.

### 9. `--monitor` mode (`   ` §11) ⬜ NOT YET

Print live stats to stderr every 5 seconds during tunnel operation.

### 10. Query type rotation (`   ` §8) 

Rotates between TXT, AAAA, A, SRV, NAPTR every 30-120 queries (randomized).
Implemented in `common/transport.c` via `transport_next_query_type()`.
- Tested in `test_integration.c::test_query_type_rotation`.

### 11. Label length / subdomain depth variation (`   ` §8) ⬜ NOT YET

Vary label fill to 70-100% and label count (2-4 labels) to avoid fingerprinting.

### 12. Token-bucket rate limiter (`   ` §8) ⬜ NOT YET

Configurable max queries-per-second, defau   50 qps.

### 13. EDNS0 size probing (`   ` §4) ⬜ NOT YET

Probe 4096, 2048, 1232, 512 and find the largest that survives end-to-end.

### 14. QCLASS probing (`   ` §2) ⬜ NOT YET

Test whether QCLASS CH (3) or HS (4) gets forwarded by the resolver.

### 15. Session resume (`   ` §9)

Session resume token generation implemented in `common/transport.c` via
`transport_generate_token()`. 8-byte random tokens stored in `transport_ctx_t`.
Server session timeout is 5 minutes. Full wire-protocol resume is a future TODO.

### 16. Integration test 

`tests/test_integration.c` has **15 comprehensive sub-tests** covering:
PSK encryption, random ISN, channel negotiation, mu  i-channel data,
CNAME chain, NS referral, upstream FQDN, all 7 channels, query rotation,
adaptive window, config defau  s, session tokens, encrypted pipeline,
stea  h entropy, and full session lifecycle (SYN→DATA→FIN).

### 17. Cross-compilation toolchain files ⬜ NOT YET

### 18. Backup channel fallback in client session logic ⬜ NOT YET

### 19. URI record type and HINFO channel activation ⬜ NOT YET

### 20. Mu  iple A/AAAA records per response ⬜ NOT YET

---

## Priority 2+ — dnscat2/iodine-Inspired Features

### 21. PSK Payload Encryption (dnscat2-inspired)  DONE

Implemented in `common/crypto.c/h`. PSK-derived XOR stream cipher using a
mixing function to generate per-packet keystreams. 2-byte nonce per packet.
- `crypto_init()`, `crypto_encrypt()`, `crypto_decrypt()`
- Wired into transport via `transport_set_psk()`
- Config fields: `psk`, `psk_len` in both client/server config
- Tested in `test_integration.c::test_psk_encryption_roundtrip`
  and `test_encrypted_transport_pipeline`

### 22. Random Initial Sequence Numbers (dnscat2-inspired)  DONE

Initial sequence numbers are now randomized using `stea  h_rand32()`
instead of starting at 0. Prevents session hijacking attacks.
- Implemented in `common/transport.c::transport_init()`
- Tested in `test_integration.c::test_random_isn`

### 23. Lazy Mode — Server-Side Pending Query Queue (iodine-inspired) 
 DONE

When the server has no data to send, it queues the DNS query instead of
responding immediately. When data arrives, it responds to the oldest
pending query. This ensures the server always has a query "in flight"
ready for instant response, dramatically improving latency.
- Implemented in `server/tunnel_server.c` with `pending_query_t` queue
- LAZY_TIMEOUT_MS = 4 seconds (stays under DNS resolver timeouts)
- Lazy drain timer fires every 500ms to prevent DNS timeouts
- Config field: `lazy_mode` (defau  : enabled)

---

## Priority 3 — Future Ideas (Beyond Current Spec)

- **TCP DNS fallback:** DNS-over-TCP to remove the 512-byte UDP ceiling.
- **DoH transport:** HTTPS POST to DoH endpoint.
- **DoT transport:** TLS-wrapped DNS on port 853.
- **EDNS0 PADDING (RFC 7830):** Pad queries to defeat traffic analysis.
- **Mu  i-server failover:** Rotate server IPs on timeout.
- **Compression negotiation:** Auto-enable LZ4 via SYN handshake.
- **DNSSEC-aware mode:** Sign responses for DNSSEC-enforcing networks.
- **Web stats dashboard:** Minimal HTTP server for live monitoring.
- **Android/iOS client:** NDK wrapper for the SOCKS5 client.
