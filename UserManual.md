# DnsTools User Manual

## Overview

DnsTools is a PowerShell module for performing iterative DNS resolution and DNSSEC validation. Unlike standard DNS utilities that rely on recursive resolvers, DnsTools queries DNS servers directly, starting from the root servers and following the delegation chain to authoritative servers.

## Installation

The module is installed in your PowerShell modules directory:
```
L:\OneDrive\Documents\WindowsPowerShell\Modules\DnsTools\0.4\
```

To load the module:
```powershell
Import-Module DnsTools
```

## Primary Function: Resolve-DnsIterative

The main function for DNS resolution.

### Basic Syntax

```powershell
# Forward DNS lookup
Resolve-DnsIterative -Name <domain> -Type <record_type> [options]

# Reverse DNS lookup (PTR)
Resolve-DnsIterative -IPAddr <ip_address>

# Dual-stack lookup (A + AAAA)
Resolve-DnsIterative -Name <domain> -DualStack
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-Name` | The domain name to resolve (validated for correct DNS syntax) |
| `-IPAddr` | IP address for reverse DNS (PTR) lookup (IPv4 or IPv6) |
| `-Type` | Record type: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, etc. |
| `-DualStack` | Query for both A and AAAA records simultaneously |
| `-ValidateDnssec` | Perform DNSSEC validation on the response |
| `-Trace` | Enable trace output for debugging resolution steps |
| `-DoT` | DNS-over-TLS server address (e.g., "1.1.1.1", "dns.google:853") |
| `-DoH` | DNS-over-HTTPS endpoint URL (e.g., "https://dns.google/dns-query") |

**Note**: Use `-Name` for forward lookups and `-Type` to specify the record type. Use `-IPAddr` for reverse (PTR) lookups - the type is automatically set to PTR.

**Note**: `-DoT` and `-DoH` are mutually exclusive. When either is specified, the resolver delegates iteration to the specified encrypted DNS server instead of performing iterative resolution from root servers.

### Supported Record Types

**Core Types**: A, NS, CNAME, SOA, MX, TXT, AAAA, SRV, NAPTR, DNAME, CAA

**DNSSEC Types**: DS, RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM, CDS, CDNSKEY

**Security / Keying Types**: SSHFP, TLSA, IPSECKEY, OPENPGPKEY, SMIMEA

**Service Types**: SVCB, HTTPS, URI

**Other**: HINFO, LOC, RP, AFSDB, WKS, SPF, TKEY, TSIG, ANY

**Note**: PTR is only available via the `-IPAddr` parameter, not `-Type`.

**Note**: Types with full structured RDATA decoding (named fields in the result, not just raw
bytes) include the core and DNSSEC types plus SSHFP, TLSA, RP, IPSECKEY, and OPENPGPKEY. RP,
IPSECKEY, and OPENPGPKEY were added in 0.5: RP exposes `MailBox`/`TxtDomain`; IPSECKEY exposes
`Precedence`/`GatewayType`/`Algorithm`/`Gateway`/`PublicKey` (gateway types 0=none, 1=IPv4,
2=IPv6, 3=domain name); OPENPGPKEY exposes the base64 `PublicKey`.

### Root hints and offline resolution

The iterative resolver bootstraps from the root servers. On import, DnsTools fetches the current
`named.root` from internic over HTTPS (TLS-authenticated) and uses it directly. When that fetch fails
(offline / blocked) it falls back, in order, to:

1. the **shipped baseline** `Helpers\RootHints-Cache.xml` - admin-only, the trusted offline anchor, and
2. a writable per-user runtime cache at `%LOCALAPPDATA%\DnsTools\RootHints-Cache.xml`, whose addresses are
   **filtered against the trusted baseline** before use, so a tampered cache cannot inject forged root IPs.

The baseline is refreshed automatically **at deploy time** (a pre-deploy hook re-fetches `named.root`), so a
freshly deployed module always ships a current root list.

If, during a session, the verified live fetch differs from the saved baseline (a genuine root change), the
module offers to persist it:

- In an interactive console you get a 5-second `Y`-to-save prompt (Enter / any other key / timeout = skip).
- Elsewhere (VS Code console, scheduled tasks, redirected input) you get a one-line notice instead.

Saving writes the verified set over the admin-only baseline, so it elevates once (UAC). **Declining or
skipping is never an error** - the session simply keeps using the verified set it already loaded. To persist
on demand at any time:

```powershell
Update-DnsRootHints            # save the verified set captured this session (one UAC)
Update-DnsRootHints -Refresh   # re-fetch named.root first, then save
```

The change-detection compares only the root names and IP addresses; the cache timestamp is ignored, so an
unchanged root list never triggers a save prompt.

## Usage Examples

### Basic Queries
```powershell
# Query A records
Resolve-DnsIterative -Name cloudflare.com -Type A

# Query MX records
Resolve-DnsIterative -Name google.com -Type MX

# Query NS records
Resolve-DnsIterative -Name microsoft.com -Type NS

# Query TXT records (e.g., SPF)
Resolve-DnsIterative -Name google.com -Type TXT
```

### Reverse DNS Lookup (PTR)
```powershell
# IPv4 reverse lookup
Resolve-DnsIterative -IPAddr 1.1.1.1
# Returns: one.one.one.one

# IPv6 reverse lookup
Resolve-DnsIterative -IPAddr 2606:4700:4700::1111
# Returns: one.one.one.one
```

### Dual-Stack Query (A + AAAA)
```powershell
# Get both IPv4 and IPv6 addresses in a single call
Resolve-DnsIterative -Name cloudflare.com -DualStack
```

### DNSSEC Validation
```powershell
# Validate DNSSEC signatures
Resolve-DnsIterative -Name cloudflare.com -Type A -ValidateDnssec

# Check DNSSEC status
$result = Resolve-DnsIterative -Name cloudflare.com -Type A -ValidateDnssec
$result.DnssecStatus  # Secure, Unsigned, Bogus, or Indeterminate
```

### CNAME Chain Resolution
The resolver automatically follows CNAME chains:
```powershell
# Follows: www.microsoft.com -> various CDN CNAMEs -> final A record
Resolve-DnsIterative -Name www.microsoft.com -Type A
```

### Debugging with Trace
```powershell
# See each step of the resolution
Resolve-DnsIterative -Name cloudflare.com -Type A -Trace
```

### Encrypted DNS Transport (DoT/DoH)

DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) provide encrypted DNS resolution. When using these parameters, the specified resolver performs recursive resolution on your behalf.

#### DNS-over-TLS (DoT)
```powershell
# Using Cloudflare's DoT server
Resolve-DnsIterative -Name cloudflare.com -Type A -DoT "1.1.1.1"

# Using Google's DoT server with explicit port
Resolve-DnsIterative -Name google.com -Type MX -DoT "dns.google:853"

# Using Quad9's DoT server
Resolve-DnsIterative -Name example.com -Type NS -DoT "dns.quad9.net"

# IPv6 DoT server with port
Resolve-DnsIterative -Name example.com -Type A -DoT "[2606:4700:4700::1111]:853"
```

#### DNS-over-HTTPS (DoH)
```powershell
# Using Google's DoH endpoint
Resolve-DnsIterative -Name cloudflare.com -Type A -DoH "https://dns.google/dns-query"

# Using Cloudflare's DoH endpoint
Resolve-DnsIterative -Name google.com -Type MX -DoH "https://1.1.1.1/dns-query"

# Using Quad9's DoH endpoint
Resolve-DnsIterative -Name example.com -Type A -DoH "https://dns.quad9.net/dns-query"
```

#### Combining with Other Options
```powershell
# DoT with DualStack
Resolve-DnsIterative -Name cloudflare.com -DualStack -DoT "1.1.1.1"

# DoH with DNSSEC validation
Resolve-DnsIterative -Name cloudflare.com -Type A -DoH "https://dns.google/dns-query" -ValidateDnssec

# DoT with trace for debugging
Resolve-DnsIterative -Name example.com -Type A -DoT "dns.google" -Trace
```

#### Common DoT/DoH Servers

| Provider | DoT Server | DoH Endpoint |
|----------|------------|--------------|
| Cloudflare | `1.1.1.1` or `1.0.0.1` | `https://1.1.1.1/dns-query` |
| Google | `dns.google` or `8.8.8.8` | `https://dns.google/dns-query` |
| Quad9 | `dns.quad9.net` or `9.9.9.9` | `https://dns.quad9.net/dns-query` |

## Output Format

### Standard Output Properties

| Property | Description |
|----------|-------------|
| `QueryName` | The domain that was queried |
| `QueryType` | Record type with code, e.g., "A(1)", "AAAA(28)" |
| `Status` | Success, BailOut, or Partial |
| `Server` | The authoritative server that provided the answer |
| `Flags` | DNS header flags, e.g., "0x8500 (QR, AA, RD)" |
| `OpCode` | Query operation type (usually QUERY) |
| `RCode` | Response code, e.g., "NOERROR(0)", "NXDOMAIN(3)" |
| `AnswerCount` | Number of answer records |
| `Answers` | Array of formatted answer records |
| `EDNS` | EDNS/OPT information if present |

### DNS Header Flags

| Flag | Meaning |
|------|---------|
| QR | Query/Response (1 = response) |
| AA | Authoritative Answer |
| TC | Truncated |
| RD | Recursion Desired |
| RA | Recursion Available |
| AD | Authenticated Data (DNSSEC) |
| CD | Checking Disabled (DNSSEC) |

### DNSSEC Validation Output

When using `-ValidateDnssec`:

| Property | Description |
|----------|-------------|
| `DnssecStatus` | Secure, Unsigned, Bogus, or Indeterminate |
| `DnssecDetails` | Array of validation steps performed |
| `DnskeyRecords` | DNSKEY records with decoded flags |
| `DsRecords` | DS records with algorithm/digest info |

## Record-Specific Output

### A/AAAA Records
```
Address: 104.16.132.229
```

### PTR Records
```
PtrName: one.one.one.one
```

### MX Records
```
Priority: Priority(10)
Exchange: mail.example.com
```

### DNSKEY Records
```
Flags: 257 (ZONE, SEP)
KeyType: KSK
Algorithm: ECDSAP256SHA256(13)
KeyTag: 12345
```

### DS Records
```
KeyTag: 12345
Algorithm: ECDSAP256SHA256(13)
DigestType: SHA-256(2)
Digest: E06D44B80B8F...
```

### RRSIG Records
```
TypeCovered: A(1)
Algorithm: ECDSAP256SHA256(13)
SignerName: cloudflare.com
Expiration: 2026-02-15 00:00:00 UTC
Inception: 2026-01-15 00:00:00 UTC
```

## Status Codes

| Status | Meaning |
|--------|---------|
| `Success` | Query resolved successfully |
| `BailOut` | Resolution failed (cycle, timeout, no answer) |
| `Partial` | DualStack: one query succeeded, one failed |

## Response Codes (RCode)

| Code | Name | Meaning |
|------|------|---------|
| 0 | NOERROR | No error |
| 1 | FORMERR | Format error |
| 2 | SERVFAIL | Server failure |
| 3 | NXDOMAIN | Domain does not exist |
| 4 | NOTIMP | Not implemented |
| 5 | REFUSED | Query refused |

## Trust Anchor Management

DNSSEC validation requires trust anchors. The module includes the current IANA root trust anchor.

### Update Trust Anchors
```powershell
# Fetch current trust anchors from IANA
Update-DnssecTrustAnchors

# Update and save to file
Update-DnssecTrustAnchors -Force
```

## Troubleshooting

### BailOut: Server-set cycle detected
This occurs when the resolver visits the same set of nameservers twice, indicating:
- The requested record type doesn't exist for this domain
- DNS delegation is broken
- Network issues preventing resolution

### Invalid DNS name syntax
The `-Name` parameter validates DNS name syntax. Ensure:
- Labels are 1-63 characters
- Only alphanumeric characters and hyphens
- No consecutive dots

### Invalid IP address syntax
The `-IPAddr` parameter validates IP address format:
- IPv4: dotted decimal (e.g., 1.1.1.1)
- IPv6: standard or compressed notation (e.g., 2001:db8::1)

### DNSSEC Status: Bogus
Indicates DNSSEC validation failed:
- Invalid signature
- Missing DNSKEY
- Expired signatures
- Chain of trust broken

### No EDNS in output
Not all servers respond with EDNS/OPT records. EDNS info appears only when the server includes it.

### DoT/DoH Transport Errors
If using `-DoT` or `-DoH` fails with "Transport error":
- **Connection refused**: The server may not support DoT/DoH or the port is blocked
- **SSL/TLS error**: Certificate validation issues (DoT)
- **HTTP error**: Invalid endpoint URL or server error (DoH)
- Verify the server address/URL is correct
- Ensure network connectivity to the DoT port (853) or HTTPS port (443)

### Invalid DoT server format
The `-DoT` parameter accepts:
- IPv4 address: `1.1.1.1`
- IPv4 with port: `8.8.8.8:853`
- Hostname: `dns.google`
- Hostname with port: `dns.google:853`
- IPv6 in brackets: `[2606:4700::1]`
- IPv6 with port: `[2606:4700::1]:853`

### Invalid DoH endpoint
The `-DoH` parameter requires an HTTPS URL:
- Must start with `https://`
- Example: `https://dns.google/dns-query`
- HTTP URLs are not accepted for security

## Version History

- **0.4**: Current version with iterative resolution, DNSSEC validation, DualStack support, CNAME chain following, PTR support with -IPAddr parameter, DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) encrypted transport options

## Support

For issues or feature requests, contact the module maintainer.
