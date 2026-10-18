# DnsTools Changelog

## v0.8

### Fixed (DNSSEC validation failed open or failed valid answers)
- `Resolve-Dnssec` and `Test-DnssecChain` tested the object returned by `Test-DnssecRrsig` (always truthy) instead of its
  `.Valid`, so an invalid signature was never rejected.
- `Resolve-DnsIterative -ValidateDnssec` reported `Secure` after checking RRSIGs against a DNSKEY fetched from the same
  untrusted resolution. Validation now authenticates keys up the DS chain to a configured trust anchor
  (new internal `Get-DnssecTrustedKey` / `Test-DnssecResponseSignature` / `Test-DnssecRrsetSignature` / `Get-DnssecDsMatchedKey`);
  every answer RRset must verify, the signer must be the owner name or an ancestor, an unsigned RRset is reported as
  `Indeterminate` rather than `Secure`.
- `Test-DnssecValidation`: a DNSKEY RRset with no RRSIG was reported SECURE; the root was declared trusted without matching the
  trust anchor; the DS RRset signature was never checked; any key in the unauthenticated DNSKEY set could sign it.
- `Resolve-Dnssec` / `Resolve-DnssecChain` / `Resolve-DnssecZone` rewritten on the same trust walk (the walk is driven by RRSIG
  signer names, so a host name that is not a zone apex no longer breaks it).
- Signed data used the packet's raw RDATA, so valid signatures on NS, CNAME, MX, SOA, PTR, SRV, NAPTR, RP and DNAME failed
  whenever the server compressed names: `DnsResourceRecord.GetCanonicalRData()` rebuilds them uncompressed and lower-cased
  (`DnsNsRecord` gained `ToWire`). Wildcard-expanded answers are now verified against the wildcard owner (RRSIG Labels).
- The root name was encoded as two zero bytes (`Get-DnssecCanonicalNameWire`), breaking every digest/signature over the root.
- Trust anchors were one per zone, so the root's second KSK overwrote the first. A zone now holds a list. The shipped
  `Helpers\trust-anchors.json` was refreshed from IANA (now KSK 20326 and 38696; the root DNSKEY RRset is signed only by 38696 since the rollover).
- `Update-DnssecTrustAnchorFile` threw under StrictMode on the absent `validUntil` attribute and never completed.
- `DnsBinaryReader.ReadBytes(0)` and zero-length RDATA returned two bytes (descending range); now empty.
- `Invoke-DnsUdpQuery` now retries over TCP when the UDP answer is truncated (TC), which signed zones such as .org need for DNSKEY.

### Fixed (resolver)
- NXDOMAIN and NODATA are returned as Final answers (raw results carry `Negative`), not as a "Server-set cycle detected" BailOut;
  SERVFAIL/REFUSED/FORMERR/NOTIMP make the resolver try the next server.
- Formatting any signed negative answer threw (NSEC/NSEC3 used non-existent property names `NextName`/`TypeBitMaps`).
- UDP socket now matches the server's address family (IPv6 roots/glue always failed before).
- UDP replies must match the query ID, QR bit and question; others are discarded until the deadline. Query IDs now come from the OS
  cryptographic RNG.
- Glue is accepted only for nameservers the referral names; `Resolve-NameserverAddress` accepts addresses only for the asked name or its CNAME chain.
- CNAME following is capped at 8; nameserver-name resolution shares its visited set down the recursion and is capped at depth 6.
- `Test-DnssecValidation` builds its zone path from real zone apexes (a name with its own SOA), so host names validate; a missing DS is UNSIGNED.
- DoT validates the server certificate (the callback that accepted everything is gone), has connect/read/write timeouts, no longer spins when
  the peer closes the connection, checks the response ID and disposes its sockets. DoH sets a timeout and an Accept header, checks the ID, disposes.

### Added / fixed (denial of existence, algorithms, DualStack)
- **Insecure delegations are now proven, not assumed.** A missing DS is accepted as "unsigned delegation" only when the parent's signed NSEC or
  NSEC3 (matching record, or an opt-out proof) shows it (`Test-DnssecDsAbsence`); an unproven missing DS stays `Indeterminate`, since it could be
  a stripped DS. New trust status `Insecure`. An answer with no RRSIG is judged by walking the zone cuts (`Get-DnssecInsecureProof`): provably in an
  unsigned zone -> `Unsigned`/`Insecure`; zone is signed -> `Bogus` (signature stripped). Verified live: microsoft.com and amazon.com are
  "provably unsigned" via the .com NSEC3 opt-out proof.
- `Find-DnssecNsec3NextCloser` hashed the query name; it now hashes the name one label below the closest encloser (RFC 5155), and compares
  ordinally. The NSEC3 helpers accept an empty salt.
- NSEC3 `Salt`, RRSIG `Signature`, zero-length `RawRData`, IPSECKEY and OPENPGPKEY keys were `$null` when empty (an `$x = if (...) {...} else {[byte[]]@()}`
  result is unrolled); now empty arrays.
- Signature algorithms 5 and 7 (RSA/SHA-1), 10 (RSA/SHA-512) and 14 (ECDSA P-384) are verified in addition to 8 and 13; RSA key lengths are validated;
  crypto objects are disposed. Ed25519 (15) was added afterwards (below); Ed448 (16) remains unsupported and throws, which callers count as a failed verification.
- DualStack now merges when the two response codes agree (it required the same random server). The merged `DnssecStatus` is the worse of the two.

- Signed NXDOMAIN and NODATA answers are authenticated (`Test-DnssecNegativeResponse`): SOA signed by the zone, then NSEC (name covered plus
  wildcard covered, or a matching NSEC listing neither the type nor a CNAME) or NSEC3 (RFC 5155 section 8.4 closest-encloser proof, or a matching
  record). `Resolve-Dnssec` and `-ValidateDnssec` use it; a stripped proof from a signed zone is `Bogus`, a provably unsigned zone is `Insecure`.
  Verified live on example.com, ietf.org, iana.org (NSEC3 NXDOMAIN) and microsoft.com (Insecure). New `Compare-DnsCanonicalName` (RFC 4034 section 6.1).
- Ed25519 (algorithm 15) is verified by a small managed RFC 8032 verifier (`Test-DnssecEd25519Signature`, compiled on first use): neither .NET
  Framework nor the .NET versions PowerShell 7 ships on have the primitive. Checked against RFC 8032 vectors and OpenSSL-made signatures under both hosts.
  Algorithm 14 verified live on fedoraproject.org.

### Fixed (second code review)
- A negative answer is only accepted as a proof when its SOA zone contains the query name; a delegation NSEC/NSEC3 (NS, no SOA) proves only
  the absence of DS, and a covering delegation record above the name, or a delegation closest encloser, is rejected. Mixed NSEC3 parameters in one
  response are Indeterminate. An NSEC3 opt-out span reports `Insecure` (an unsigned delegation may exist), not `Secure`. Stops a signed root/parent
  NSEC being replayed as an NXDOMAIN or NODATA proof for another name.
- Wildcard-expanded answers (RRSIG Labels fewer than the owner's labels) need the signed NSEC/NSEC3 proof that the exact name does not exist
  (`Test-DnssecWildcardProof`, RFC 4035 section 5.3.4); without it the answer is Bogus (Indeterminate if no authority section was supplied).
- One failing RRSIG no longer marks an RRset Bogus when another RRSIG on it verifies (key and algorithm rollovers publish several).
- A signature made with an algorithm this module cannot verify, or a DS using only an unsupported algorithm or digest type, now makes the data
  `Insecure` (RFC 4035 section 5.2, RFC 6840 section 5.2) instead of `Bogus`.
- `Test-DnssecValidation`: PASSED now also requires the target record to validate.
- The parent of a zone is its enclosing zone (first ancestor with an SOA), not the name with one label removed.
- `Update-DnssecTrustAnchorFile`: `-Force` no longer overrides `-WhatIf`; IANA's detached signature (root-anchors.p7s) is verified, with the signing chain
  required to end at the pinned ICANN Root CA, before the anchors are used (`-SkipSignatureCheck` is the explicit opt-out).
- The TCP retry after a truncated UDP reply checks the reply ID, QR bit and question like a UDP reply (`Test-DnsReplyMatch`).
- DoH works on Windows PowerShell 5.1 (it never loaded System.Net.Http there); `-DoT '[ipv6]'` without a port and IPv6-literal DoH URLs are accepted.
### Fixed (third code review)
- **Anchor-signing chain could be forged.** Only `NotTimeValid` was inspected, so a leaf signed by an attacker's own key, naming the ICANN root as
  its issuer and shipped beside the genuine public root certificate, passed the pinned-thumbprint check. Now every chain status except `UntrustedRoot`
  is fatal and the chain must be built (`Test-DnssecAnchorSignerChain`, with a forged-leaf test).
- **A CNAME chain cut short was accepted as Secure.** Validation now follows the CNAME chain from the query name; the name it ends at needs data of
  the queried type or an authenticated NXDOMAIN/NODATA, otherwise the answer is not Secure. Resolve-DnsIterative now follows a CNAME for every type
  except CNAME and the DNSSEC types (it used to for A/AAAA only).
- **NSEC wildcard proof** covers the NEXT CLOSER name (RFC 4035 section 5.3.4), as the NSEC3 branch already did; and a queried literal `*.example.com`
  owner (RRSIG Labels excludes the `*`) is no longer mistaken for an expansion.
- **DS denial from the child zone** (the child's own SOA/apex NSEC) is rejected: only the parent can prove a DS absent. A single SOA RRset is used.
- A parent signature on the DS, or a DNSKEY signature, made with an unsupported algorithm is `Insecure` (the root: `Indeterminate`), not `Bogus`.
- `Test-DnsReplyMatch` accepts a REFUSED/FORMERR/... reply with an empty question section (it used to look like a full timeout) but not one claiming
  success, and rejects replies with more than one question. DoT and DoH replies now go through it (ID, QR and question), not just the ID.
- The root DNSKEY RRset only includes records owned by the root.
- DoH: one shared `HttpClient` (no new TLS handshake per query) and a non-`https://` endpoint is refused.
### Known, not yet fixed
- Ed448 (algorithm 16) is not supported (no SHAKE256 / curve448 in .NET) and throws "Unsupported DNSSEC algorithm", which counts as a failed
  verification. NSEC3 opt-out and Wildcard-synthesised NODATA denials (other than the DS case) are reported `Indeterminate` rather than proven.

## v0.7

### Breaking changes
PSScriptAnalyzer cleanup pass.
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

### Added
- Function-trace facility (`Enable-MyFunctionTrace -Option 1-3`, `Disable-MyFunctionTrace`,
  `Clear-MyFunctionTraceLog`, `Clear-MyFunctionTraceArchive`), vendored, replacing the module's own
  `Write-Trace`. Per-window trace files (`FunctionTrace-Session-<Id>.log` under
  `C:\ProgramData\FunctionTrace`); `-Option` is required.
- Catch-audit housekeeping (`Clear-MyCatchAuditArchive`).
- `Protect-MyFunctionTraceFolder` (2026-09-21): locks the trace-log folder so other local users cannot read your
  logs (`-Check` reports without elevation). `Enable-MyFunctionTrace` warns once when the folder is not locked
  down; `$env:MyFunctionTraceNoAclWarning = '1'` silences it.

### Fixed
- `Resolve-Dnssec` and `Test-DnssecValidation` called `Resolve-DnsIterative` without `-Raw`, so they
  received the formatted result instead of the raw shape they expect and never validated a zone
  correctly. Added `-Raw` at all five call sites.
- `Resolve-DnssecChain` called three functions that did not exist. Implemented them:
  `Get-DnssecZonePath`, `Get-RootTrustAnchor`, `Resolve-DnssecZone` (all internal).
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
