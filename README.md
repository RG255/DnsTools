# DnsTools

A PowerShell module for iterative DNS resolution and DNSSEC validation. Unlike standard
DNS utilities that rely on recursive resolvers, DnsTools queries DNS servers directly -
starting from the root servers and following the delegation chain to authoritative servers.

## Key Features

- Iterative DNS resolution (root -> TLD -> authoritative)
- Full DNSSEC chain validation (DNSKEY, DS, RRSIG, NSEC, NSEC3)
- DNS over TLS (DoT) and DNS over HTTPS (DoH) transport
- Support for A, AAAA, MX, NS, TXT, CNAME, SRV, CAA, DNAME, NAPTR, PTR, SOA, SSHFP, TLSA, RP, IPSECKEY, OPENPGPKEY record types
- DNSSEC trust anchor management

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+

## Installation

Deploy with the repo's standard deployment script (installs to the admin-only, AllUsers
Program Files module path):

```powershell
powershell.exe -NoProfile -File "D:\PowerShellScripts\Modules\Deploy-Modules.ps1" -Module DnsTools -Version 0.6
```

Then import:

```powershell
Import-Module DnsTools -RequiredVersion 0.6
```

## Quick Start

```powershell
# Iterative resolution
Resolve-DnsIterative -Name 'example.com' -Type A

# DNSSEC validation
Resolve-DnssecName -Name 'example.com'

# DNS over TLS
Resolve-DnsIterative -Name 'example.com' -Type A -UseDot
```

## Documentation

See [UserManual.md](UserManual.md) for full usage and function reference.
