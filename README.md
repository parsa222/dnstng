# DnsTNG — DNS Tunneling New Generation

Yes, this is a DNS tunnel. Yes, you have seen these before. This one just happens to use every single
field in the DNS protocol that can carry a byte without immediately crashing a resolver, plus three
backup channels for when your network administrator finally gets around to blocking DNS entirely.

---

## What It Is

DnsTNG tunnels arbitrary TCP traffic (via a local SOCKS5 proxy) through DNS queries and responses.
The client runs inside a censored network that permits DNS. The server runs as an authoritative
nameserver outside. The domestic recursive resolver between them does the heavy lifting for free.

The tool is written in C11. It compiles clean with `-Wall -Wextra -Werror -pedantic` and passes
AddressSanitizer with zero errors, because broken tools that corrupt your stack are less useful
than working ones.

---

## Why This Exists: Network Restrictions and the IRGFW

DnsTNG is built for heavily restricted networks — specifically ones like the IRGFW (Iran's
national filtering system), which blocks VPNs via DPI, hijacks foreign DNS resolvers, strips
TXT records to defeat tunnel tools, and flags high-entropy subdomains as suspicious traffic.
The one path it cannot close is recursive DNS: domestic resolvers must reach outside
authoritative nameservers to resolve any domain, and that path is the tunnel.

## Prior Art and Why This Is Different

**iodine** tunnels IP over DNS using NULL/TXT/CNAME/MX records. It is reliable on permissive
networks but uses high-entropy base32 labels that are trivially detected by entropy-aware DPI,
supports only a single downstream channel, and has no fallback when DNS is filtered.

**dnstt** (David Fifield) tunnels a QUIC stream over DNS TXT records with cleaner engineering
than iodine. TXT records are specifically what the IRGFW blocks first. When TXT is gone,
dnstt stops. Base32 encoding again produces detectable entropy. Single channel, no fallback.

DnsTNG's approach: negotiate at session start which channels survive, spread data across
every available DNS field, and fall back to SMTP/OCSP/CRL if DNS itself is blocked.

| Capability | iodine | dnstt | DnsTNG |
|---|---|---|---|
| Record types | NULL/TXT/CNAME/MX | TXT only | NAPTR, SOA, NULL, TXT, CAA, SRV, CNAME, AAAA, A (auto) |
| Downstream channels | Single record type | Single TXT record | Answer + Authority NS + Additional glue + TTL bits + EDNS0 |
| Encoding | Base32 (high entropy) | Base32 (high entropy) | Base36 (lower entropy) |
| Bandwidth multiplier | None | None | CNAME chain (up to 8x) + NS referral chain |
| Fallback if DNS blocked | None | None | SMTP (port 25), OCSP (port 80), CRL (port 80) |
| Anti-detection | None | Minimal | Jitter, noise queries, query-type rotation, TTL mimicry |
| Typical bandwidth | ~1 KB/s | ~1–3 KB/s | ~20–200 KB/s |

---

## How It Works

### The Basic Idea

```
[Local App]  <-- SOCKS5 --> [Client: 127.0.0.1:1080]
                                      |
                         DNS query: <base36_payload>.<session>.t.<domain>
                                      |
                         [Recursive Resolver] (not yours, not controlled)
                                      |
                         [Server: authoritative NS for <domain>]
                                      |
                         Decodes payload, proxies TCP, encodes response
                                      |
                         DNS response: multiple records, all carrying data
                                      |
                         [Recursive Resolver] (still not yours)
                                      |
                                   [Client]
                                      |
                            [Local App receives data]
```

### Upstream Encoding (Client to Server)

Data travels upstream encoded in the subdomain labels of the DNS query FQDN:

```
<base36_data>.<session_id_hex>.t.<tunnel_domain>
```

Example: `3x9kp2r.0042.t.tunnel.example.com`

Base36 (digits 0-9 plus lowercase a-z) is used because it looks like a normal subdomain.
Base64 is not used because capital letters and plus signs look suspicious in DNS and some
resolvers will mangle them. Each label is at most 63 characters. The total FQDN is at most
253 characters. These are DNS limits, not design choices.

Additional upstream bytes come from:
- **Transaction ID (TXID):** 2 bytes per query, if the recursive resolver preserves it
- **EDNS0 custom option 65001:** variable bytes, if the resolver passes unknown EDNS0 options through

### Downstream Encoding (Server to Client)

This is where it gets interesting. A single DNS response can carry data in multiple fields
simultaneously. Instead of the traditional "put everything in a TXT record and hope for 255 bytes",
DnsTNG uses every available container:

#### Primary Record Channels (Answer Section)

| Record Type | Capacity per Record | How Data Is Stored |
|---|---|---|
| NAPTR | ~500 bytes | Data in the Regexp and Replacement fields |
| SOA | ~526 bytes | Data split across MNAME/RNAME labels and 5 numeric fields (serial, refresh, retry, expire, minimum) |
| SVCB / HTTPS | variable | Data in SvcParams key-value area |
| HINFO | ~510 bytes | Data split across CPU string and OS string fields |
| NULL | up to 65535 bytes | Raw binary, no structure required |
| TXT | ~255 bytes | Standard text data |
| CAA | ~253 bytes | Data in the value field |
| SRV | ~260 bytes | 6 bytes in priority/weight/port, rest in target name labels |
| CNAME | ~253 bytes | Data encoded in the domain name labels |
| AAAA | 16 bytes | Raw binary as IPv6 address |
| A | 4 bytes | Raw binary as IPv4 address |

Multiple records of the same type can be returned in one response. Three NAPTR records = ~1500
bytes downstream from a single query. The server picks the highest-capacity type that works
and packs as many records as it can.

#### Fragment Protocol

Each record's data payload starts with a 3-byte header:
```
Byte 0-1: data_offset (uint16_t big-endian) — where in the full stream this fragment starts
Byte 2:   fragment_len (uint8_t) — how many data bytes follow
```

The client collects all fragments from all channels in a response and reassembles them. This
is how multiple small channels combine into one larger effective bandwidth.

#### Multi-Channel Secondary Fields

Beyond the answer records, DnsTNG packs data into additional DNS response fields:

**Authority Section (NS records):**
Each NS name encodes a chunk of data as base36 labels: `<base36_data>.ns<i>.<domain>`.
Resolvers are required by the DNS protocol to pass the Authority section through. This gives
roughly 2 x 200 bytes per response of additional downstream capacity for free.

**Additional Section (Glue A/AAAA records):**
Glue records' IP addresses carry raw binary data. Four A records = 16 bytes; four AAAA records
= 64 bytes. Also required to be passed through by resolvers.

**TTL Steganography:**
The lower 24 bits of each record's TTL field carry 3 bytes of data. The upper 8 bits are kept
at zero so the TTL stays in a range that looks plausible (0-16 million seconds, which is
admittedly still suspicious but less so than 0xDEADBEEF). This applies to every record in
the response: answer, authority, and additional.

**EDNS0 Option 65001:**
The server includes a custom EDNS0 option (code 65001, in the private/experimental range) with
downstream data. If the recursive resolver passes unknown EDNS0 options through, this is free
extra bandwidth.

**Transaction ID:**
The 16-bit TXID field in the DNS response carries 2 bytes of session sequence metadata.

### CNAME Chaining (Bandwidth Multiplier)

A single client query can trigger multiple recursive lookups, each carrying a response:

```
Client queries: x.t.tunnel.example.com A
  Server responds: CNAME -> <data_chunk_1>.c0.t.tunnel.example.com
    Server responds: CNAME -> <data_chunk_2>.c1.t.tunnel.example.com
      Server responds: CNAME -> <data_chunk_3>.c2.t.tunnel.example.com
        Server responds: A 0.0.0.1 (final, also carries last data bytes)
```

Result: 1 client query triggers 4 server responses. Each CNAME target name encodes a chunk
of data in its labels. The client parses the full chain and reassembles all chunks.
Default chain depth is 3. Maximum is 8 (beyond that, resolvers start returning SERVFAIL and
you have achieved nothing except annoying your resolver's operator).

### NS Referral Chaining

An alternative multiplier that looks more like normal DNS delegation behavior. The server
responds with NS records in the authority section pointing to sub-nameservers it also controls.
The resolver follows the delegation, triggering another recursive lookup. Data is encoded in
the NS names: `<base36_data>.ns<i>.<domain>`.

More stealthy than CNAME chains because NS referrals are expected behavior for authoritative
nameservers. Less reliable because some resolvers cache referrals aggressively.

---

## Backup Channels

For when your firewall administrator has discovered that DNS can be abused and has blocked
outbound port 53, DnsTNG includes three independent fallback channels.

### SMTP Tunnel (Port 25 / 587)

Data travels upstream encoded in the EHLO hostname of an SMTP session:
```
EHLO <base36_data>.t.<domain>
```

The server (which must run a compatible SMTP listener) responds with data encoded in
SMTP 250-continuation lines:
```
250-<base36_downstream_data>
250 ok
```

SMTP port 25 is frequently left open because email must flow. Port 587 (submission) is
also usable. This is, depending on your perspective, either clever or unfortunate.

### OCSP Channel (Port 80)

OCSP (Online Certificate Status Protocol) traffic is rarely blocked because blocking it would
break TLS certificate validation for every browser on the network. DnsTNG encodes data in
OCSP-like HTTP GET requests:

```
GET /ocsp/<base36_data> HTTP/1.0
Host: ocsp.<domain>
Accept: application/ocsp-response
```

The server returns downstream data in a custom HTTP header:
```
X-Tunnel-Data: <hex_encoded_data>
```

The response also includes a valid-looking `Content-Type: application/ocsp-response` header
to reinforce the illusion.

### CRL Channel (Port 80)

Similar to OCSP but uses Certificate Revocation List fetch patterns:

```
GET /crl/<session_id>/<base36_data>.crl HTTP/1.0
Host: crl.<domain>
Accept: application/pkix-crl
```

Downstream data again comes in `X-Tunnel-Data` headers. CRL fetches are HTTP (not HTTPS),
which means no TLS to deal with and they pass through almost every proxy and firewall.

---

## Setup

### DNS Zone Configuration

You need a domain. Point an NS record for a subdomain at a server you control:

```
; In your domain's zone file:
tunnel.yourdomain.com.  IN  NS  ns1.tunnel.yourdomain.com.
ns1.tunnel.yourdomain.com.  IN  A  <your-server-ip>
```

The server must be reachable on UDP port 53 from the internet. It also needs to be able to
make outbound TCP connections (for proxying traffic). If your server cannot make outbound
connections, you have bigger problems than this tool can solve.

### Build

```bash
# Install dependencies (Debian/Ubuntu)
apt-get install cmake libuv1-dev libcares-dev liblz4-dev

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

This produces two binaries: `dnstunnel-client` and `dnstunnel-server`.

For a fully static build (no glibc dependency):
```bash
# Install musl toolchain
apt-get install musl-tools musl-dev

# Static build
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_C_COMPILER=musl-gcc \
         -DCMAKE_EXE_LINKER_FLAGS="-static"
make -j$(nproc)
```

For ARM64 (Android/phones):
```bash
apt-get install gcc-aarch64-linux-gnu
cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-linux-gnu.cmake
make -j$(nproc)
```

### Server Setup

```bash
# Basic startup
sudo ./dnstunnel-server \
    --domain tunnel.yourdomain.com \
    --listen 0.0.0.0:53 \
    --upstream 8.8.8.8

# With config file
sudo ./dnstunnel-server --config /etc/dnstunnel/server.conf
```

Server config (`server.conf`):
```ini
domain = tunnel.yourdomain.com
listen = 0.0.0.0:53
upstream_dns = 8.8.8.8
log_level = info
active_channels = auto
cname_chain_depth = 3
ns_chain_depth = 2
ttl_encoding = stealth
```

### Client Setup

```bash
# Run the channel probe first to see what works
./dnstunnel-client \
    --domain tunnel.yourdomain.com \
    --resolver 10.0.0.1 \
    --check

# Start the tunnel
./dnstunnel-client \
    --domain tunnel.yourdomain.com \
    --resolver 10.0.0.1 \
    --listen 127.0.0.1:1080

# Configure your browser/app to use SOCKS5 proxy at 127.0.0.1:1080
```

Client config (`client.conf`):
```ini
domain = tunnel.yourdomain.com
resolver = 10.0.0.1
listen = 127.0.0.1:1080
record_types = auto
encode_mode = base36
active_channels = auto
cname_chain_depth = 3
ns_chain_depth = 2
ttl_encoding = stealth
smtp_host =
smtp_port = 25
ocsp_host =
ocsp_port = 80
crl_host =
crl_port = 80
log_level = info
```

---

## Usage Reference

```
dnstunnel-client [options]
  --config <file>          Load configuration file
  --domain <domain>        Tunnel domain
  --resolver <ip>          DNS resolver IP to query through
  --listen <addr:port>     SOCKS5 listen address (default: 127.0.0.1:1080)
  --check                  Run full channel probe and exit
  --benchmark              Measure actual throughput for 10 seconds
  --loglevel <level>       debug | info | warn | error
  --help                   Show this message

dnstunnel-server [options]
  --config <file>          Load configuration file
  --domain <domain>        Tunnel domain
  --listen <addr:port>     DNS listen address (default: 0.0.0.0:53)
  --upstream <ip>          Upstream DNS resolver for non-tunnel queries
  --loglevel <level>       debug | info | warn | error
  --help                   Show this message
```

---

## Channel Probe Output

Running `--check` produces a report like this:

```
=== DNS Record Type Support ===
[*] Testing A record tunnel                        OK (4 bytes/response)
[*] Testing AAAA record tunnel                     OK (16 bytes/response)
[*] Testing CNAME record tunnel                    OK (~180 bytes/response)
[*] Testing MX record tunnel                       OK
[*] Testing TXT record tunnel                      BLOCKED (timeout)
[*] Testing NULL record tunnel                     BLOCKED (timeout)
[*] Testing NAPTR record tunnel                    OK (~500 bytes/response)
[*] Testing SRV record tunnel                      OK (~260 bytes/response)
[*] Testing CAA record tunnel                      OK (~253 bytes/response)
[*] Testing SVCB record tunnel                     UNSUPPORTED
[*] Testing SOA record tunnel                      OK (~526 bytes/response)
[*] Testing EDNS0 (4096 byte UDP)                  OK

=== Multi-Channel Support ===
[*] Testing multi-channel: TXID                    OK (TXID preserved)
[*] Testing multi-channel: EDNS0 option            UNKNOWN (requires live server)
[*] Testing multi-channel: Authority NS            UNKNOWN (requires live server)
[*] Testing multi-channel: Additional glue         UNKNOWN (requires live server)
[*] Testing multi-channel: TTL encoding            OK (TTL values preserved)

[*] Measuring RTT.................................... avg 180ms, loss 0%
[*] Recommended config: NAPTR records, channels: TXID+TTL, window=8
[*] Estimated bandwidth: ~1 KB/s up, ~4 KB/s down
```

---

## Reliability Layer

DNS is UDP. UDP drops packets, reorders them, and duplicates them for fun. DnsTNG handles
this with a transport layer on top:

- **Sequence numbers** on every packet (2 bytes)
- **Acknowledgments** from server to client, carried in DNS response data
- **CRC16-CCITT checksum** on every packet header
- **Retransmission** with exponential backoff (initial 500ms, max 10s, factor 1.5)
- **Ring buffer** (64 slots) for retransmission tracking
- **Sliding window** (default 8 concurrent in-flight queries)

---

## Stealth Features

- **Jitter:** Request timing has ±20% random variation. Uses `getrandom()` syscall,
  not `rand()`, because `rand()` is predictable and this is not the 1990s.
- **Noise domains:** When idle, the client sends occasional lookups for real domains
  (google.com, cloudflare.com, etc.) to blend in with normal DNS traffic.
- **Entropy management:** Base36 encoding keeps the Shannon entropy of query names lower
  than Base64. Higher entropy is a DPI fingerprint.
- **TTL mimicry:** In stealth mode, TTL steganography keeps values in a believable range
  rather than setting them to arbitrary 32-bit integers.
- **Query type rotation:** Periodically rotates between working record types to avoid
  fixed patterns.

---

## Project Layout

```
dnstunnel/
├── CMakeLists.txt
├── README.md           (this file)
├── LTMemory.MD         (full original specification)
├── STmemory.md         (session state: implemented, TODO, future ideas)
├── client/
│   ├── main.c          CLI parsing and entry point
│   ├── socks5.c/.h     SOCKS5 proxy server (RFC 1928)
│   ├── tunnel_client.c/.h  Client-side tunnel logic
│   └── check.c/.h      --check, --benchmark modes
├── server/
│   ├── main.c          CLI parsing and entry point
│   ├── dns_server.c/.h UDP DNS listener
│   ├── tunnel_server.c/.h  Server-side session management
│   ├── chain.c/.h      CNAME chaining and NS referral chaining
│   └── proxy.c/.h      TCP proxy (exit node)
├── common/
│   ├── channel.c/.h    Multi-channel pack/unpack (all DNS fields)
│   ├── encode.c/.h     Base36 / Base32 encoding
│   ├── transport.c/.h  Reliability layer (seq, ack, retransmit, window)
│   ├── dns_packet.c/.h DNS wire protocol, RDATA builders for all types
│   ├── compress.c/.h   LZ4 compression wrapper
│   ├── config.c/.h     Config file parser
│   ├── log.c/.h        Logging
│   ├── stealth.c/.h    Jitter, noise domains, entropy measurement
│   ├── smtp_channel.c/.h  SMTP backup tunnel
│   ├── ocsp_channel.c/.h  OCSP covert channel
│   ├── crl_channel.c/.h   CRL covert channel
│   └── util.c/.h       Error codes, CRC16-CCITT
├── third_party/
│   ├── lz4.c / lz4.h   Bundled LZ4 single-file distribution
└── tests/
    ├── test_encode.c       Encoding round-trip tests
    ├── test_transport.c    Reliability layer tests
    ├── test_dns_packet.c   DNS packet crafting/parsing tests
    ├── test_channel.c      Multi-channel pack/unpack tests
    ├── test_chain.c        CNAME / NS chain tests
    └── run_tests.sh        Run all tests
```

---

## Bandwidth Estimates

These are rough maximums under ideal conditions (resolver that passes everything through,
no packet loss, 100ms RTT). Reality will be worse.

| Configuration | Downstream | Upstream |
|---|---|---|
| TXT only (baseline) | ~20 KB/s | ~10 KB/s |
| NAPTR single record | ~40 KB/s | ~10 KB/s |
| NAPTR x4 records | ~160 KB/s | ~10 KB/s |
| NAPTR + multi-channel | ~200 KB/s | ~15 KB/s |
| NAPTR + CNAME chain x4 | ~640 KB/s | ~10 KB/s |
| Full multi-channel + chain | ~800 KB/s | ~20 KB/s |

In practice you will get a fraction of these numbers because recursive resolvers cache
aggressively, strip unknown record types, and generally treat your creativity as a bug.

