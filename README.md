# DnsTools

A PowerShell module for iterative DNS resolution and DNSSEC validation. Unlike standard
DNS utilities that rely on recursive resolvers, DnsTools queries DNS servers directly -
starting from the root servers and following the delegation chain to authoritative servers.

## Key Features

- Iterative DNS resolution (root -> TLD -> authoritative)
- DNSSEC validation anchored to the IANA root trust anchor (DNSKEY, DS, RRSIG), including authenticated denial of existence (NSEC, NSEC3) and signature algorithms 5, 7, 8, 10, 13, 14 and 15
- DNS over TLS (DoT) and DNS over HTTPS (DoH) transport
- Support for A, AAAA, MX, NS, TXT, CNAME, SRV, CAA, DNAME, NAPTR, PTR, SOA, SSHFP, TLSA, RP, IPSECKEY, OPENPGPKEY record types
- DNSSEC trust anchor management

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+

## Installation

Clone or copy this repository into a folder named after the version, inside a module folder on your
`$env:PSModulePath`:

```powershell
# PowerShell 7
git clone https://github.com/RG255/DnsTools "C:\Program Files\PowerShell\Modules\DnsTools\0.8"
# Windows PowerShell 5.1
git clone https://github.com/RG255/DnsTools "C:\Program Files\WindowsPowerShell\Modules\DnsTools\0.8"
```

Then import:

```powershell
Import-Module DnsTools -RequiredVersion 0.8
```

## Quick Start

```powershell
# Iterative resolution
Resolve-DnsIterative -Name 'example.com' -Type A

# DNSSEC validation
Resolve-DnssecName -Name 'example.com'

# DNS over TLS
Resolve-DnsIterative -Name 'example.com' -Type A -DoT '1.1.1.1'
```

## Documentation

See [UserManual.md](UserManual.md) for full usage and function reference.
