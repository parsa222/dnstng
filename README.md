## removed everthing because VIBE coding is is a big mess
# currently working on it locally (i spent more time on reading the inefficient ai code rather than actually doing sth  )
using iodine (https://github.com/yarrick/iodine) what a legened lol!

# DnsTNG — DNS Tunneling New Generation

A DNS tunnel built on [iodine](https://github.com/yarrick/iodine), enhanced with base36 encoding
for DPI evasion and support for every useful DNS record type.

---

## What It Is

DnsTNG tunnels IP traffic through DNS queries and responses. The client runs inside a restricted
network that permits DNS. The server runs as an authoritative nameserver outside. The recursive
resolver between them carries the tunnel traffic.

Built on iodine's proven protocol (handshake, lazy mode, fragmentation, raw UDP mode), with these
additions:

- **Base36 encoding** — `[0-9a-z]` alphabet (lower entropy than base32, harder for DPI to flag)
- **13 DNS record types** — NULL, PRIVATE, TXT, SRV, MX, CNAME, A, AAAA, SOA, NAPTR, SVCB, HTTPS, CAA
- **EDNS0** — advertises 4096-byte payload for larger responses
- **Automatic codec negotiation** — upgrades to the best encoding the path supports
- **Automatic query type detection** — finds the highest-bandwidth record type that works

---

## Why This Exists

DnsTNG is designed for heavily restricted networks like the IRGFW, which:
- Blocks VPNs via DPI
- Hijacks foreign DNS resolvers
- Strips TXT records
- Flags high-entropy subdomains

The one path it cannot close is recursive DNS resolution itself. DnsTNG uses that path, with
base36 encoding to keep subdomain entropy low enough to avoid triggering statistical filters.

---

## Supported DNS Record Types

| Type | Code | Data Carrier | Bandwidth |
|------|------|-------------|-----------|
| NULL | 10 | Raw binary RDATA | Highest (binary) |
| PRIVATE | 65399 | Raw binary RDATA | Highest (binary) |
| CAA | 257 | Value field (binary) | High (binary) |
| TXT | 16 | TXT string data | High (encoded) |
| SRV | 33 | Multiple target hostnames | Medium (name-encoded) |
| MX | 15 | Multiple exchange hostnames | Medium (name-encoded) |
| SVCB | 64 | TargetName field | Low (name-encoded) |
| HTTPS | 65 | TargetName field | Low (name-encoded) |
| SOA | 6 | MNAME field | Low (name-encoded) |
| NAPTR | 35 | Replacement field | Low (name-encoded) |
| CNAME | 5 | Canonical name | Low (name-encoded) |
| A | 1 | CNAME answer to A query | Low (name-encoded) |
| AAAA | 28 | CNAME answer to AAAA query | Low (name-encoded) |

The client auto-detects which types pass through your resolver and picks the best one.





Configure DNS records at your registrar:

```
tunnel.example.com.    NS    ns.tunnel.example.com.
ns.tunnel.example.com. A     <your-vps-ip>
```

Start the server:

```bash
./bin/iodined -f -c -P <password> -u nobody 10.0.0.1/24 tunnel.example.com
```

### Client Setup

```bash
./bin/iodine -f -P <password> tunnel.example.com
```

### Client Options

```
-T TYPE     Force DNS record type (NULL, TXT, SOA, NAPTR, SVCB, HTTPS, CAA, ...)
-O CODEC    Force downstream encoding (Base32, Base36, Base64, Base64u, Base128, Raw)
-r          Skip raw UDP mode (use when behind strict NAT/firewall)
-I SECS     Max interval between requests (default: 4)
-m SIZE     Max downstream fragment size (default: auto)
-M SIZE     Max upstream hostname length (default: 255)
-P PASS     Password for authentication
-4 / -6     Force IPv4 or IPv6 only
```

---

##  Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Docker Network                      │
│                  172.30.0.0/24                        │
│                                                       │
│  ┌─────────────┐  DNS queries  ┌──────────────┐      │
│  │   Client    │──────────────>│   CoreDNS    │      │
│  │ 172.30.0.3  │               │ 172.30.0.4   │      │
│  │             │               │              │      │
│  │ iodine      │               │ Forwards     │      │
│  │ (tunnel)    │               │ tunnel.test   │      │
│  └──────┬──────┘               │ to server    │      │
│         │                      └──────┬───────┘      │
│         │                             │              │
│         │ TUN: 10.0.0.x               │ DNS forward  │
│         │                             │              │
│  ┌──────┴──────────────────────┬──────┴───────┐      │
│  │         Server              │              │      │
│  │       172.30.0.2            │              │      │
│  │                             │              │      │
│  │  iodined (DNS + TUN)        │              │      │
│  │  TUN: 10.0.0.1/24          │              │      │
│  └─────────────────────────────┘              │      │
│                                                       │
└─────────────────────────────────────────────────────┘
```

The CoreDNS container acts as a recursive resolver, forwarding `tunnel.test` queries to the
server. This simulates the real-world scenario where the client's ISP resolver forwards
queries to your authoritative nameserver.

---

## Encoding Details

### Base36

DnsTNG defaults to base36 encoding (`[0-9a-z]`) for upstream data. (insead of base32 , more data and less suspicious)

- **Alphabet**: `0123456789abcdefghijklmnopqrstuvwxyz` (36 symbols)
- **Block ratio**: 5 raw bytes → 8 encoded characters (same as base32)
- **Entropy**: ~5.17 bits/char (vs 5.0 for base32, but lowercase-only looks more natural)
- **Case-insensitive**: survives DNS resolver case folding

During handshake, the codec is auto-negotiated. If the path supports it, the tunnel upgrades
to Base128 for maximum throughput. Base36 is the fallback for restrictive resolvers.
