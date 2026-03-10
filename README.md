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

| Capability | iodine | dnscat2 | DnsTNG |
|---|---|---|---|
| Record types | NULL/TXT/CNAME/MX/SRV | TXT only | NAPTR, SOA, NULL, TXT, CAA, SRV, CNAME, AAAA, A (auto) |
| Downstream channels | Single record type | Single TXT record | Answer + Authority NS + Additional glue + TTL bits + EDNS0 |
| Encoding | Base32/64/128 (auto) | Raw | Base36 (lower entropy) |
| Bandwidth multiplier | None | None | CNAME chain (up to 8x) + NS referral chain |
| Fallback if DNS blocked | None | None | SMTP (port 25), OCSP (port 80), CRL (port 80) |
| Anti-detection | Minimal | None | Jitter, noise queries, query-type rotation, TTL mimicry |
| Payload encryption | None | ECDH + Salsa20 | PSK-derived XOR stream cipher |
| Lazy mode |  (key innovation) | No |  (iodine-inspired) |
| Adaptive polling |  (auto) | No |  (100ms → 4s ramp) |
| Random ISN | No |  (anti-hijack) |  (dnscat2-inspired) |
| Query type rotation | Manual (-T flag) | No |  Automatic (30-120 query intervals) |
| Adaptive window | No | No |  EWMA-based RTT (2-32 slots) |
| Session resume | Reconnect from scratch | Reconnect from scratch |  Token-based resume |
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

Example: `3x9kp2r.0042.t.example.com`

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

#### DNS Packet Anatomy — Where Your Data Hides

The following diagram shows a complete DNS response packet with every field that DnsTNG uses
to carry tunnel data. Fields marked with `◄── DATA` carry hidden payload bytes.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        DNS HEADER (12 bytes)                         │
├────────────────────┬─────────────────────────────────────────────────┤
│  Transaction ID    │ 0xA3F1                           ◄── DATA (2B) │
│  (16 bits)         │ Carries session sequence metadata               │
├────────────────────┼─────────────────────────────────────────────────┤
│  Flags             │ 0x8180 (standard response, no error)            │
│  QD/AN/NS/AR count │ QD=1  AN=3  NS=2  AR=5                         │
└────────────────────┴─────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                    QUESTION SECTION (1 record)                        │
├──────────────────────────────────────────────────────────────────────┤
│  QNAME: 3x9kp2r.0042.t.tunnel.example.com                           │
│         ^^^^^^^^                                                     │
│         Upstream data (base36-encoded in subdomain labels)           │
│  QTYPE: NAPTR    QCLASS: IN                                         │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                    ANSWER SECTION (3 NAPTR records)                   │
├──────────────────────────────────────────────────────────────────────┤
│  Record 1: tunnel.example.com  NAPTR                                 │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  TTL: 0x00A1B2C3                              ◄── DATA (3B) │    │
│  │       ~~^^^^^^^^                                             │    │
│  │       Upper 8 bits kept low (looks normal)                   │    │
│  │       Lower 24 bits = 3 bytes of hidden data                 │    │
│  ├──────────────────────────────────────────────────────────────┤    │
│  │  Order: 10    Preference: 100                                │    │
│  │  Flags: "u"   Service: "sip+E2U"                             │    │
│  │  Regexp:  "<3-byte frag header><~200 bytes>    ◄── DATA"     │    │
│  │  Replace: "<3-byte frag header><~200 bytes>    ◄── DATA"     │    │
│  │           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^                  │    │
│  │           [offset_hi][offset_lo][frag_len][payload...]        │    │
│  └──────────────────────────────────────────────────────────────┘    │
│  Record 2: (same structure, ~500 more bytes)         ◄── DATA       │
│  Record 3: (same structure, ~500 more bytes)         ◄── DATA       │
│                                                                      │
│  Total answer section: ~1500 data bytes + 9 TTL-stego bytes          │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                    AUTHORITY SECTION (2 NS records)                   │
├──────────────────────────────────────────────────────────────────────┤
│  Record 1:                                                           │
│    NAME: tunnel.example.com                                          │
│    TYPE: NS                                                          │
│    TTL:  0x00112233                                   ◄── DATA (3B) │
│    RDATA: 7kp2r9x4m.ns0.tunnel.example.com           ◄── DATA      │
│            ^^^^^^^^^^                                                │
│            Base36-encoded data chunk in NS name labels               │
│                                                                      │
│  Record 2:                                                           │
│    RDATA: a3b5c7d9.ns1.tunnel.example.com             ◄── DATA      │
│    TTL:   0x00445566                                  ◄── DATA (3B) │
│                                                                      │
│  Total authority section: ~400 data bytes + 6 TTL-stego bytes        │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                    ADDITIONAL SECTION (5 records)                     │
├──────────────────────────────────────────────────────────────────────┤
│  Glue A records (4 records):                                         │
│    ns0.tunnel.example.com  A  0xDE.0xAD.0xBE.0xEF    ◄── DATA (4B) │
│    ns1.tunnel.example.com  A  0xCA.0xFE.0xBA.0xBE    ◄── DATA (4B) │
│    ns2.tunnel.example.com  A  0x12.0x34.0x56.0x78    ◄── DATA (4B) │
│    ns3.tunnel.example.com  A  0x9A.0xBC.0xDE.0xF0    ◄── DATA (4B) │
│    (IP addresses ARE the data — raw binary)                          │
│    TTL per record:                                    ◄── DATA (3B) │
│                                                                      │
│  EDNS0 OPT record (1 record):                                       │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  NAME: . (root)   TYPE: OPT (41)   UDP size: 4096           │    │
│  │  Option Code: 65001 (private/experimental)                   │    │
│  │  Option Data: <variable length binary>         ◄── DATA      │    │
│  │               Raw tunnel payload bytes                       │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Total additional section: 16 bytes (glue) + EDNS0 + 12 TTL-stego   │
└──────────────────────────────────────────────────────────────────────┘

Summary: one DNS response, ~2000+ data bytes hidden across all fields
```

**What the recursive resolver sees:** A perfectly valid DNS response with NAPTR records,
NS delegation, glue records, and an EDNS0 extension. Every field conforms to the DNS RFC.
There is nothing syntactically wrong with this packet. The data is hiding in plain sight.

**What the IRGFW sees:** DNS traffic on port 53 between a domestic resolver and a foreign
authoritative nameserver. The query is for an obscure record type (NAPTR) with a normal-looking
subdomain. The response contains standard DNS structures. Unless the firewall specifically
inspects the entropy of every DNS field (which would break legitimate DNS), the tunnel is
invisible.

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
Client queries: x.t.example.com A
  Server responds: CNAME -> <data_chunk_1>.c0.t.example.com
    Server responds: CNAME -> <data_chunk_2>.c1.t.example.com
      Server responds: CNAME -> <data_chunk_3>.c2.t.example.com
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
outbound port 53, DnsTNG includes three independent fallback channels. These are not a theoretical
exercise — they exist because the IRGFW (Iran's national filtering system) has been observed
blocking DNS tunneling traffic during internet shutdowns while leaving other protocols open.

### Why Three Backup Channels?

The IRGFW does not block everything at once. Its filtering is applied in stages:

1. **First:** VPNs and known circumvention tools are blocked via DPI (always active)
2. **Second:** DNS over port 53 gets additional scrutiny — TXT records stripped, high-entropy
   subdomains flagged, sometimes port 53 blocked entirely during shutdowns
3. **Third:** Port 80 HTTP is rarely fully blocked because it would break the entire
   domestic web infrastructure
4. **Fourth:** Port 25/587 SMTP is almost never blocked because domestic email would stop

DnsTNG's fallback order matches this escalation: DNS first, then SMTP/OCSP/CRL over
HTTP/SMTP ports. If one channel is blocked, the client can try the next.

---

### SMTP Tunnel (Port 25 / 587)

#### How It Works

The SMTP tunnel disguises data as email server handshakes. Every SMTP conversation starts
with the client sending `EHLO` followed by a hostname. DnsTNG puts tunnel data in that hostname.

```
┌──────────────────────────────────────────────────────────────────┐
│                     SMTP Tunnel Wire Format                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  UPSTREAM (Client → Server):                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  EHLO 3x9kp2r4m.t.tunnel.example.com\r\n                  │  │
│  │       ^^^^^^^^^^                                           │  │
│  │       Base36-encoded tunnel payload                        │  │
│  │       Looks like: "mail server announcing its hostname"    │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  DOWNSTREAM (Server → Client):                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  250-7kp2r9x4ma3b5c7\r\n                                  │  │
│  │  250-d9e1f3g5h7i9j1\r\n                                   │  │
│  │  250 ok\r\n                                                │  │
│  │      ^^^^^^^^^^^^^^^^                                      │  │
│  │      Base36-encoded downstream data in continuation lines  │  │
│  │      "250-" = more data follows, "250 " = end              │  │
│  │      Looks like: "server listing its SMTP extensions"      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Why It Works Against the IRGFW

- **Port 25/587 is open:** Iran has domestic email infrastructure (mail.ir, etc.) that
  depends on SMTP. Blocking port 25 would stop all email delivery between domestic mail
  servers and foreign ones. The IRGFW has never fully blocked SMTP during any shutdown.
- **DPI doesn't flag EHLO:** The SMTP EHLO command is the very first thing any mail server
  sends. It is the most common SMTP command on the internet. DPI rules that flag EHLO
  hostnames would produce millions of false positives from legitimate email traffic.
- **The conversation is syntactically valid SMTP:** A firewall watching the stream sees
  a standard SMTP handshake. The `250-` continuation responses are exactly what real
  mail servers send when listing their ESMTP extensions. The data in the hostname and
  continuation lines is base36 — lowercase alphanumeric, which looks like a normal domain name.

#### Setup

**Server side:** The DnsTNG server needs a TCP listener on port 25 or 587 that speaks the
SMTP tunnel protocol. Configure your server:

```ini
# server.conf
domain = tunnel.yourdomain.com
bind_addr = 0.0.0.0
bind_port = 53

# SMTP backup channel will listen on this port
# Make sure port 25 is open in your server's firewall
```

Make sure no other mail server (Postfix, Exim, etc.) is already bound to port 25 on the
same interface. If you have an existing mail server, use port 587 instead.

**DNS setup for SMTP:** Add an MX record pointing to your tunnel server so the domain
looks like it handles email:

```
; In your domain's zone file
tunnel.yourdomain.com.  IN  MX  10  mail.tunnel.yourdomain.com.
mail.tunnel.yourdomain.com.  IN  A  <your-server-ip>
```

**Client side:**

```ini
# client.conf
domain = tunnel.yourdomain.com
smtp_host = <your-server-ip>
smtp_port = 25
```

Or use port 587 if port 25 is filtered:

```ini
smtp_port = 587
```

---

### OCSP Channel (Port 80)

#### How It Works

OCSP (Online Certificate Status Protocol) is how browsers check if a TLS certificate has been
revoked. Every time you visit an HTTPS website, your browser may send an OCSP request to the
certificate's OCSP responder. DnsTNG disguises tunnel data as these OCSP requests.

```
┌──────────────────────────────────────────────────────────────────┐
│                     OCSP Channel Wire Format                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  UPSTREAM (Client → Server):                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  GET /ocsp/3x9kp2r4ma3b5c7 HTTP/1.0\r\n                   │  │
│  │  Host: ocsp.tunnel.example.com\r\n                         │  │
│  │  Accept: application/ocsp-response\r\n                     │  │
│  │  Connection: keep-alive\r\n                                │  │
│  │  \r\n                                                      │  │
│  │            ^^^^^^^^^^^^^^^^^^                               │  │
│  │            Base36-encoded tunnel payload in URL path        │  │
│  │            Looks like: "browser checking certificate status"│  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  DOWNSTREAM (Server → Client):                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  HTTP/1.0 200 OK\r\n                                       │  │
│  │  Content-Type: application/ocsp-response\r\n               │  │
│  │  X-Tunnel-Data: deadbeefcafebabe1234567890abcdef\r\n       │  │
│  │  \r\n                                                      │  │
│  │                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^            │  │
│  │                 Hex-encoded downstream data                 │  │
│  │                 Hidden in a custom HTTP header              │  │
│  │  Looks like: "CA server responding with cert status"       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Why It Works Against the IRGFW

- **OCSP is essential for HTTPS:** Every modern browser checks certificate revocation via
  OCSP. If the IRGFW blocks OCSP traffic, every HTTPS website would show certificate errors
  for Iranian users. This would break domestic banking sites, government portals, and
  e-commerce — which the authorities rely on remaining functional.
- **Port 80 is open:** OCSP uses plain HTTP (not HTTPS) on port 80, per RFC 6960. This is
  by design — you cannot use TLS to check if your TLS certificate is valid (chicken-and-egg).
  Port 80 is the last port any national firewall blocks.
- **The Host header looks legitimate:** `ocsp.tunnel.example.com` looks like any other OCSP
  responder domain. Real OCSP responders have domains like `ocsp.digicert.com`,
  `ocsp.letsencrypt.org`, etc. The pattern is identical.
- **The path structure is normal:** Real OCSP GET requests encode the OCSP request in the URL
  path as base64 data. DnsTNG uses base36 which looks similar — a long alphanumeric string
  in the URL path.
- **The response is indistinguishable:** The `Content-Type: application/ocsp-response` header
  makes the response look like a legitimate OCSP reply. The `X-Tunnel-Data` header blends in
  with the many custom headers that web servers routinely add.

#### Setup

**Server side:** The DnsTNG server needs an HTTP listener on port 80 that responds to
`/ocsp/*` requests. Configure your server:

```ini
# server.conf
domain = tunnel.yourdomain.com
```

If you are running a web server (Nginx, Apache) on port 80 already, configure it to reverse-proxy
`/ocsp/*` requests to the DnsTNG server's internal port:

```nginx
# Nginx example — proxy OCSP-looking requests to DnsTNG
server {
    listen 80;
    server_name ocsp.tunnel.yourdomain.com;

    location /ocsp/ {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

**DNS setup for OCSP:** Add an A record for the OCSP subdomain:

```
ocsp.tunnel.yourdomain.com.  IN  A  <your-server-ip>
```

**Client side:**

```ini
# client.conf
domain = tunnel.yourdomain.com
ocsp_host = <your-server-ip>
ocsp_port = 80
```

---

### CRL Channel (Port 80)

#### How It Works

CRL (Certificate Revocation List) is the older alternative to OCSP. Instead of checking one
certificate at a time, browsers periodically download a full list of revoked certificates from
a CRL Distribution Point. DnsTNG disguises tunnel data as these CRL download requests.

```
┌──────────────────────────────────────────────────────────────────┐
│                     CRL Channel Wire Format                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  UPSTREAM (Client → Server):                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  GET /crl/00000001/3x9kp2r4m.crl HTTP/1.0\r\n             │  │
│  │  Host: crl.tunnel.example.com\r\n                          │  │
│  │  Accept: application/pkix-crl\r\n                          │  │
│  │  Connection: keep-alive\r\n                                │  │
│  │  \r\n                                                      │  │
│  │           ^^^^^^^^ ^^^^^^^^^^                               │  │
│  │           seq num  Base36-encoded tunnel payload            │  │
│  │           The ".crl" extension makes it look like a file   │  │
│  │           Looks like: "browser downloading revocation list" │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  DOWNSTREAM (Server → Client):                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  HTTP/1.0 200 OK\r\n                                       │  │
│  │  Content-Type: application/pkix-crl\r\n                    │  │
│  │  X-Tunnel-Data: deadbeefcafebabe1234567890abcdef\r\n       │  │
│  │  \r\n                                                      │  │
│  │                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^            │  │
│  │                 Hex-encoded downstream data                 │  │
│  │  Looks like: "CA server serving revocation list file"      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### Why It Works Against the IRGFW

- **CRL is HTTP-only by design:** Unlike OCSP which can technically use HTTPS, CRL fetches
  are almost always plain HTTP. This is because CRL Distribution Points are embedded in
  X.509 certificates, and the URLs are overwhelmingly `http://` (not `https://`). This means
  the traffic is expected to be unencrypted on port 80.
- **Blocking CRL breaks TLS:** If the IRGFW blocks CRL downloads, browsers that rely on CRL
  (rather than OCSP) for revocation checking will either show certificate errors or fall back
  to "soft fail" (accepting potentially revoked certificates). Either outcome disrupts normal
  HTTPS browsing for all Iranian users.
- **The URL pattern is standard:** Real CRL URLs look like `http://crl.digicert.com/sha2-ev-server-g3.crl`
  or `http://crl.globalsign.com/gs/gsorganizationvalsha2g2.crl`. DnsTNG's
  `/crl/<seq>/<data>.crl` follows the exact same pattern — a path ending in `.crl`.
- **CRL fetches are periodic:** Browsers download CRLs on a schedule (every few hours to
  days). This means CRL traffic is bursty, not continuous — exactly the pattern DnsTNG's
  adaptive polling produces.
- **The Accept header is correct:** `application/pkix-crl` is the official MIME type for
  CRL files (RFC 5280). The response looks exactly like a real CRL server.

#### Why CRL and OCSP Are Separate Channels

You might ask: both OCSP and CRL run on port 80, so why have both?

1. **Different DPI signatures:** A firewall rule that blocks `/ocsp/*` URLs would not catch
   `/crl/*.crl` requests, and vice versa. Having both means you survive partial blocking.
2. **Different Host headers:** `ocsp.example.com` and `crl.example.com` are different
   domains. If the IRGFW blocks one, the other may still work.
3. **Different traffic patterns:** OCSP is request-response (one cert at a time). CRL is
   bulk download (periodic). Using whichever pattern is less suspicious on the current
   network is an advantage.

#### Setup

**Server side:** Same as OCSP — an HTTP listener on port 80 that responds to `/crl/*`
requests.

If co-hosting with a web server:

```nginx
# Nginx example — proxy CRL-looking requests to DnsTNG
server {
    listen 80;
    server_name crl.tunnel.yourdomain.com;

    location /crl/ {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

**DNS setup for CRL:** Add an A record for the CRL subdomain:

```
crl.tunnel.yourdomain.com.  IN  A  <your-server-ip>
```

**Client side:**

```ini
# client.conf
domain = tunnel.yourdomain.com
crl_host = <your-server-ip>
crl_port = 80
```

---

### Backup Channel Fallback Strategy

When the primary DNS tunnel is blocked, the client can switch to backup channels.
The intended fallback order is:

```
1. DNS tunnel (port 53)         ← Primary, highest bandwidth
       |
       | (blocked by IRGFW?)
       v
2. OCSP channel (port 80)       ← First fallback, looks like cert validation
       |
       | (OCSP URLs blocked?)
       v
3. CRL channel (port 80)        ← Second fallback, different URL pattern
       |
       | (CRL URLs blocked?)
       v
4. SMTP tunnel (port 25/587)    ← Last resort, looks like email handshake
```

**Current status:** The backup channel implementations (SMTP, OCSP, CRL) are complete as
standalone modules with full send/receive/connect/disconnect support. The automatic fallback
logic that switches the client session from DNS to backup channels when DNS is detected as
blocked is a TODO item (see TODO.md §18). For now, backup channels can be configured manually
in the client config.

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

### Quick Build (Ubuntu)

The fastest way to install dependencies and build on Ubuntu (20.04 / 22.04 / 24.04):

```bash
./build.sh
```

This installs all required packages, compiles both binaries, and runs the test suite.
The binaries end up in `build/`.

### Manual Build (Ubuntu)

If you prefer to do it yourself:

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config \
    libuv1-dev libc-ares-dev liblz4-dev

# Build with GNU Make (recommended)
make clean && make all

# Or build with CMake
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

This produces two binaries: `dnstunnel-client` and `dnstunnel-server` in `build/`.

### Run Tests

```bash
# GNU Make
make tests

# Or CMake
cd build && ctest --output-on-failure
```

All 6 test binaries must pass: `test_encode`, `test_transport`, `test_dns_packet`,
`test_channel`, `test_chain`, `test_integration`.

The integration test (`test_integration`) covers 15 end-to-end scenarios including:
- PSK encryption round-trip
- Random ISN verification
- Channel negotiation (SYN → SYN-ACK with bitmask intersection)
- Multi-channel data through NAPTR+CAA
- CNAME chain round-trip (3-hop)
- NS referral round-trip
- Upstream FQDN encode/decode pipeline
- All 7 DNS channels simultaneously
- Query type rotation (TXT → AAAA → A → SRV → NAPTR)
- Adaptive window sizing (EWMA-based RTT)
- Config defaults (PSK, lazy_mode, channels)
- Session resume token generation
- Encrypted transport pipeline (both directions)
- Stealth entropy measurement
- Full session lifecycle (SYN → SYN-ACK → DATA → FIN)

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
psk = my-secret-tunnel-key
lazy_mode = 1
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
psk = my-secret-tunnel-key
lazy_mode = 1
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
  --psk <passphrase>       Pre-shared key for payload encryption
  --check                  Run full channel probe and exit
  --benchmark              Measure actual throughput for 10 seconds
  --loglevel <level>       debug | info | warn | error
  --help                   Show this message

dnstunnel-server [options]
  --config <file>          Load configuration file
  --domain <domain>        Tunnel domain
  --listen <addr:port>     DNS listen address (default: 0.0.0.0:53)
  --upstream <ip>          Upstream DNS resolver for non-tunnel queries
  --psk <passphrase>       Pre-shared key for payload encryption
  --lazy-mode <0|1>        Enable lazy mode (default: 1)
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

- **Random sequence numbers** on every packet (2 bytes, randomized ISN like dnscat2)
- **Acknowledgments** from server to client, carried in DNS response data
- **CRC16-CCITT checksum** on every packet header
- **Retransmission** with exponential backoff (initial 500ms, max 10s, factor 1.5)
- **Ring buffer** (64 slots) for retransmission tracking
- **Adaptive sliding window** (EWMA-based RTT, range 2-32, default 8)

### Random Initial Sequence Numbers (dnscat2-inspired)

Each new transport context starts with a random 16-bit ISN generated using
`getrandom()`. This prevents session hijacking attacks where an adversary
who knows the session ID guesses the next sequence number. Combined with
the random session ID, this gives ~48 bits of per-session entropy — the same
approach dnscat2 uses.

### Adaptive Window Size (EWMA-based)

The window size (number of in-flight queries allowed) is dynamically adjusted based
on measured round-trip times. The algorithm:

1. **Measure RTT** for each query-response pair (send timestamp → ack timestamp)
2. **Compute EWMA**: `rtt_ewma = 0.875 × rtt_ewma + 0.125 × sample` (same formula as TCP)
3. **Adjust window**:
   - If RTT improved (new EWMA < previous): increase window by 1 (max 32)
   - If RTT degraded >25% (new EWMA > previous × 1.25): decrease window by 1 (min 2)
   - Otherwise: keep current window (stable)

This means the tunnel automatically speeds up on good networks and throttles on
congested ones, without manual tuning.

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
  fixed patterns. Rotates every 30-120 queries (randomized interval) among
  TXT → AAAA → A → SRV → NAPTR.

---

## Payload Encryption (dnscat2-inspired)

DnsTNG includes a PSK (Pre-Shared Key) encryption layer inspired by dnscat2's
encryption protocol. While dnscat2 uses ECDH key exchange with Salsa20, DnsTNG uses
a simpler but effective approach designed for the DNS tunnel use case:

### How It Works

1. **Key Derivation**: The PSK (any passphrase up to 64 bytes) is hashed through a
   mixing function inspired by SipHash. The mixing uses 4 × 32-bit state words
   initialized from the fractional parts of √2, √3, √5, √7 (same constants used
   by SHA-256). The PSK bytes are absorbed into this state, then 8 extra mixing rounds
   produce a 32-byte key.

2. **Per-Packet Keystream**: For each packet, a 2-byte nonce is prepended. The keystream
   is generated by hashing `(key_hash || nonce || block_index)` through the same mixing
   function. This produces 16-byte keystream blocks that are XORed with the payload.

3. **Wire Format**:
   ```
   [nonce_hi][nonce_lo][encrypted_data...]
   ```
   Total overhead: 2 bytes per packet (the nonce).

4. **Nonce Management**: The nonce is incremented for each sent packet. Unlike dnscat2,
   strict anti-replay is not enforced because DNS retransmissions are extremely common
   (recursive resolvers gratuitously re-send queries). The nonce ensures each packet
   produces different ciphertext even for identical payloads.

### What This Provides

- **Payload obfuscation**: Defeats pattern-matching DPI that looks for tunnel protocol
  signatures in DNS response payloads
- **Per-packet uniqueness**: Each packet produces different ciphertext even for identical
  data, defeating replay-based detection
- **Zero external dependencies**: No OpenSSL, no libsodium, no mbedTLS

### What This Does NOT Provide

- This is NOT a cryptographically strong cipher. An attacker with the binary can
  reverse-engineer the mixing function. It's designed to defeat passive DPI inspection,
  not active cryptanalysis.
- No forward secrecy (same PSK forever). For stronger guarantees, run SSH/TLS inside
  the tunnel.

### Configuration

```ini
# In server.conf and client.conf (must match!)
psk = my-secret-passphrase-here
```

Both client and server must use the same PSK. If the PSK doesn't match, decrypted
payloads will be garbage and the CRC-16 checksum in the transport layer will reject them.

---

## Lazy Mode (iodine-inspired)

Lazy mode is iodine's single biggest performance innovation, and DnsTNG implements it
with the same approach.

### The Problem

In a normal DNS tunnel, the client sends a query and the server immediately responds.
When the server has no data to send, it responds with an empty ACK. This means:

- The client must keep polling (sending queries) to check for downstream data
- Each poll has the full round-trip latency (100-500ms through recursive resolvers)
- When data finally arrives at the server, it must wait for the next client poll

### The Solution: Delayed Response

In lazy mode, the server **does not respond to a query immediately** if it has no data
to send. Instead, it holds the query in a pending queue. When data arrives:

1. Server takes the **oldest pending query** from the queue
2. Responds to it immediately with the data
3. The client receives the data with near-zero latency

This means the server always has a DNS query "in flight" ready to send data on.
The client's next poll query replaces the consumed one in the queue.

### Timing and Timeouts

- **Queue size**: 4 pending queries per session (LAZY_QUEUE_SIZE)
- **Lazy timeout**: 4 seconds (LAZY_TIMEOUT_MS). If a query hasn't been answered
  in 4 seconds, the server responds with an empty ACK. This stays under most
  recursive resolver timeouts (typically 5-10 seconds per RFC 1035).
- **Drain timer**: Every 500ms, the server checks for expired pending queries and
  responds to them. This prevents DNS SERVFAIL errors from impatient resolvers.

### How It Interacts with Other Features

- **SYN/SYN-ACK**: Always responded immediately (never queued)
- **DATA packets**: The server responds to the oldest pending query (if any),
  then queues the current query. This is the key insight: when data arrives,
  the response goes to the previously queued poll, not the current request.
- **POLL packets**: If there's already a pending query, the old one gets an
  empty ACK, and the new poll takes its place in the queue.

### Configuration

```ini
# In server.conf
lazy_mode = 1    # 1 = enabled (default), 0 = disabled
```

---

## Adaptive Poll Interval (iodine-inspired)

The client's poll interval (how often it sends DNS queries when idle) adapts to
traffic patterns.

### Behavior

| State | Interval | Description |
|---|---|---|
| Active data | 100ms | Minimum interval, maximum throughput |
| Ramping down | 100ms + 50ms per idle poll | Gradually slows when no data flows |
| Fully idle | 4000ms | Maximum interval, minimum DNS query rate |

When data starts flowing again (client has data to send), the interval immediately
drops back to 100ms.

### Why This Matters

- **Detection avoidance**: A fixed high-frequency poll (e.g., 50ms = 20 queries/second)
  is an obvious fingerprint. Normal DNS traffic is bursty, not periodic.
- **Resource efficiency**: An idle tunnel sending 20 qps wastes bandwidth and CPU
  for both client and server.
- **iodine comparison**: iodine uses a similar approach with a default 4-second
  idle interval, reducing to 1 second under some conditions. DnsTNG uses a smoother
  linear ramp instead of iodine's step function.

---

## Query Type Rotation

The tunnel rotates between different DNS record types to avoid fingerprinting.

### How It Works

1. A rotation list is maintained: `[TXT, AAAA, A, SRV, NAPTR]`
2. Every 30-120 queries (randomized interval using `getrandom()`), the tunnel
   switches to the next type in the list
3. The randomized interval prevents periodic patterns that DPI could detect

### Compared to iodine

iodine uses the `-T` flag to manually force a specific record type. It also has
auto-detection that picks the "best" type, but once selected, it stays fixed.
DnsTNG rotates automatically, which:

- Makes the traffic pattern look more like normal DNS (which uses various record types)
- Reduces the chance of a single record type being blocked mid-session
- Doesn't require the user to know which types work

---

## Session Resume (dnscat2-inspired)

When a network outage occurs, the client can resume an existing session instead of
starting over.

### How It Works

1. During session setup, the server generates an 8-byte random session token
   and stores it in `transport_ctx_t.session_token`
2. If the connection drops, the client can include this token in a new SYN
   to prove it's the same client
3. The server matches the token and resumes the session state (sequence numbers,
   window, channel negotiation) instead of creating a new session

### Current Status

The token generation infrastructure is implemented (`transport_generate_token()`).
The full wire-protocol resume (including token in SYN payload) is a TODO item.

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
│   ├── tunnel_client.c/.h  Client-side tunnel logic (adaptive polling)
│   └── check.c/.h      --check, --benchmark modes
├── server/
│   ├── main.c          CLI parsing and entry point
│   ├── dns_server.c/.h UDP DNS listener
│   ├── tunnel_server.c/.h  Server-side session management (lazy mode)
│   ├── chain.c/.h      CNAME chaining and NS referral chaining
│   └── proxy.c/.h      TCP proxy (exit node)
├── common/
│   ├── channel.c/.h    Multi-channel pack/unpack (all DNS fields)
│   ├── crypto.c/.h     PSK payload encryption (dnscat2-inspired)
│   ├── encode.c/.h     Base36 / Base32 encoding
│   ├── transport.c/.h  Reliability layer (seq, ack, retransmit, adaptive window)
│   ├── dns_packet.c/.h DNS wire protocol, RDATA builders for all types
│   ├── compress.c/.h   LZ4 compression wrapper
│   ├── config.c/.h     Config file parser (PSK, lazy_mode fields)
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
    ├── test_transport.c    Reliability layer tests (random ISN)
    ├── test_dns_packet.c   DNS packet crafting/parsing tests
    ├── test_channel.c      Multi-channel pack/unpack tests
    ├── test_chain.c        CNAME / NS chain tests
    ├── test_integration.c  15 end-to-end tests (crypto, ISN, lazy, channels, etc.)
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

