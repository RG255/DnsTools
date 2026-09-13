# DnsTools Changelog

## v0.7

### Breaking changes
PSScriptAnalyzer cleanup pass (see the repo's `_PlanningDocs\_Repo\2026-09-12_PSSA-Cleanup-Plan.md`).
Zero external usage confirmed (public repo, 0 stars/forks/subscribers/releases) - hard renames, no
back-compat aliases:

- `Update-DnsRootHints` -> `Update-DnsRootHintsFile`
- `Get-DnssecTrustAnchors` -> `Get-DnssecTrustAnchorStore`
- `Import-DnssecTrustAnchors` -> `Import-DnssecTrustAnchorFile`
- `Update-DnssecTrustAnchors` -> `Update-DnssecTrustAnchorFile`
- `Initialize-DnssecTrustAnchors` -> `Initialize-DnssecTrustAnchorFile`
- `ConvertFrom-DnsWireBytes` -> `ConvertFrom-DnsWireBuffer`
- `ConvertTo-DnsWireBytes` -> `ConvertTo-DnsWireBuffer`
- `Get-DnsToolsTypes` -> `Get-DnsToolsType`
- Internal-only: `Initialize-Folders` -> `Initialize-Folder`, `Publish-Variables` -> `Publish-Variable`

### Removed
- `Helpers\TestClassinFunc.ps1` (dead scratch content - hardcoded wrong path, self-commented-out call
  site, zero references).

### Fixed
- Added `PSAvoidTrailingWhitespace` stripping to every file via the shared formatter (48 files).
- Added a `PSScriptAnalyzerSettings.psd1` excluding parser-noise rules (`TypeNotFound`,
  `MemberAlreadyDefined`, `AmbiguousTypeReference`) and the deliberate `PSAvoidUsingWriteHost` choice.
- Added/corrected `[OutputType(...)]` on `Get-Psd1Data`, `ConvertTo-ReverseDnsName`,
  `Resolve-NameserverAddress`.
- Added inline `SuppressMessageAttribute` justifications for `PSAvoidUsingEmptyCatchBlock`
  (`Write-Trace`), `PSUseShouldProcessForStateChangingFunctions` (`New-DnsQueryPacket`,
  `Update-DnsRootHintsFile`, and the fixture builders in `Helpers\Generate-Fixtures.ps1`), and two
  rule false positives (`PSUseSingularNouns` on `Test-DnssecNsec3Nodata`, `PSUseOutputTypeCorrectly`
  on `Resolve-NameserverAddress`).

## v0.6

### Changes
- Added explicit `FunctionsToExport` to the manifest so the module autoloads on first command use (no manual `Import-Module`).
- Added a 30-second timeout to the IANA trust-anchor and root-hints web requests (`Update-DnssecTrustAnchorFile`, `Get-RootHintsObject`) so a hung download cannot block import/refresh indefinitely.
- Declared `PowerShellVersion = '5.0'` in the manifest to match the module's `#requires`.

### Fixed
- `Invoke-RootHintsBaselineOffer` (an internal module-init helper, auto-invoked at import) is no longer exported as a public command; it is marked internal in the export table so it cannot be re-triggered by hand.
- Reconciled the manifest `FunctionsToExport` with the runtime export table (`Update-DnsRootHintsFile` and `Invoke-RootHintsBaselineOffer` now have explicit table entries).
- Fixed the placeholder `ProjectUri` (now points at the real repository) and stray trailing whitespace in the `Tags` array.

## v0.5.2

### New Record Types
- RP (Responsible Person) - `MailBox` and `TxtDomain` fields
- IPSECKEY - `Precedence`, `GatewayType`, `Algorithm`, `Gateway` (none / IPv4 / IPv6 / domain-name) and `PublicKey`
- OPENPGPKEY - base64 `PublicKey`

### Changes
- `Resolve-DnsIterative`, `Format-DnsIterativeResult`, `DnsResourceRecord` and the QtypeMap now handle RP, IPSECKEY and OPENPGPKEY (query + parse + format + round-trip encode)
- Root hints hardening: the runtime cache now lives at `%LOCALAPPDATA%\DnsTools\RootHints-Cache.xml` and is validated against the trusted (admin-only) baseline before use, so a tampered cache cannot redirect resolution to forged root servers
- Root hints stay current: the baseline is refreshed at deploy time, and when a live verified fetch differs from the baseline the module offers to persist it (a timed prompt in an interactive console, a one-line notice otherwise) - declining or non-interactive use is never an error

### New Commands
- `Update-DnsRootHintsFile` - persist the verified root hints to the protected baseline (elevates once; `-Refresh` re-fetches `named.root` first)

---

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
