# DnsTools Changelog

## v0.5

### New Record Types
- URI record type - priority, weight and target URI fields

### Changes
- Updated `Resolve-DnsIterative` and `Format-DnsIterativeResult` to support URI records
- Updated `DnsResourceRecord` to handle URI RDATA parsing

---

## v0.4

### Features
- Iterative DNS resolution from root servers - bypasses recursive resolvers to query authoritative servers directly
- DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) transport support
- DNSSEC validation - full chain-of-trust verification including RRSIG, DS, DNSKEY, NSEC and NSEC3
- Dual-stack resolution - simultaneous A and AAAA queries
- Reverse DNS (PTR) lookups via `-IPAddr` parameter
- Comprehensive record type support: A, AAAA, NS, MX, TXT, CNAME, SOA, SRV, NAPTR, DNAME, CAA, SSHFP, TLSA and all DNSSEC types
- NSEC3 closest encloser proof and authenticated denial of existence
- Trace mode for step-by-step resolution debugging

### Record Types Added in v0.4
- CAA, DNAME, NAPTR, PTR, SOA, SSHFP, TLSA class implementations
- ConvertFrom-Dns* parsing functions replacing earlier Parse-* functions

### Testing
- Pester test suite covering classes, RDATA parsing, wire format compression, canonical wire encoding, DoT/DoH transport, DNSSEC canonicalization, cryptography, chain validation and resolver edge cases
