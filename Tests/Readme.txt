# DNS Toolkit for PowerShell

A fully self‑contained DNS, DNSSEC, and transport‑layer toolkit written entirely in PowerShell.  
Implements:

- DNS wire format (reader/writer)
- Full DNS packet model
- EDNS(0)
- DNSSEC (DNSKEY, DS, RRSIG, NSEC, NSEC3)
- Canonicalization (RFC 4034)
- Iterative resolver with cycle protection
- DNS-over-TLS (DoT)
- DNS-over-HTTPS (DoH)
- Trust anchor management
- Synthetic fixture builder
- Comprehensive Pester test suite

This module is designed for deterministic testing, forensic analysis, and deep protocol inspection.

---

## 📦 Installation

Clone the repository and import the module:

```powershell
Import-Module ./DnsToolkit.psm1
