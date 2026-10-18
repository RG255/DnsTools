<#
		.SYNOPSIS
		DNS and DNSSEC resolution, validation, and module-level initialization.

		.DESCRIPTION
		This module provides a complete toolkit for performing DNS iterative resolution,
		DNSSEC validation, chain-of-trust evaluation, trust-anchor management, and
		wire-format parsing. It is designed for deterministic, standards-compliant
		DNSSEC analysis and forensic-grade DNS inspection.

		The module initializes:
			- Root server hints
			- DNSSEC trust anchors
			- DNS record type maps
			- DNS class maps
			- DNSSEC algorithm and digest maps
			- EDNS option maps
			- RCODE and OpCode maps
			- TLSA, SSHFP, and NSEC3 flag maps
			- Module-level variables and environment metadata

		This header replaces the original module header and includes a consolidated
		reference for deprecated DNS record types and their modern replacements.

		.NOTES
		This module is part of a DNSSEC-focused toolkit emphasizing:
			- Deterministic validation
			- Canonical wire-format correctness
			- Full chain-of-trust traversal
			- Negative validation (NSEC/NSEC3)
			- Reproducible debugging and trace output

		Ordering of maps, variables, and function tables is intentional and preserved.

		# ---------------------------------------------------------------------------
		# DNS RECORD DEPRECATION SUMMARY
		# ---------------------------------------------------------------------------

		The following DNS RR types are deprecated, obsolete, or SHOULD NOT be used.
		Replacement guidance is included for operational clarity.

		- HINFO (13)
				Deprecated due to fingerprinting and privacy concerns.
				Replacement: Do not publish; document host info out-of-band.

		- RP (17)
				Deprecated; contact information should not be stored in DNS.
				Replacement: WHOIS or HTTPS contact pages.

		- AFSDB (18)
				Obsolete; AFS ecosystem is effectively dead.
				Replacement: None; do not use.

		- LOC (29)
				Not formally deprecated but discouraged due to privacy concerns.
				Replacement: Avoid; document location out-of-band.

		- SPF (99)
				Deprecated by RFC 7208.
				Replacement: TXT records.

		- TKEY (249)
				Deprecated; replaced by TSIG for authenticated dynamic updates.
				Replacement: TSIG (250).

		- TA (32768)
				Deprecated; replaced by DS-based trust anchors configured out-of-band.
				Replacement: DS chain of trust.

		- DLV (32769)
				Deprecated; IETF retired DLV.
				Replacement: Standard DNSSEC validation via DS chain.

		- CERT (37)
				Not deprecated but largely superseded for DANE usage.
				Replacement: TLSA (52) for DANE-style bindings.

		- KX (36)
				Obsolete; replaced by MX for mail and SRV/SVCB/HTTPS for service endpoints.
				Replacement: MX, SRV, SVCB, HTTPS.

		# ---------------------------------------------------------------------------
		# DNSSEC CONTEXT
		# ---------------------------------------------------------------------------

		This module implements:
			- Canonical name and RR canonicalization
			- RRSIG validation (time windows, key matching, digest matching)
			- DNSKEY <-> DS validation
			- NSEC and NSEC3 negative validation
			- Opt-Out logic for NSEC3
			- Closest encloser and next-closer derivation
			- Trust anchor enforcement

		DNSSEC validation relies on:
			- DnssecAlgorithmMap
			- DnssecDigestMap
			- TypeCoveredMap
			- Nsec3FlagsMap
			- TrustAnchorsInitialized

		# ---------------------------------------------------------------------------
		# ROOT HINTS AND TRUST ANCHORS
		# ---------------------------------------------------------------------------

		Root server hints are loaded from:
				Helpers\Get-RootHints.ps1

		Trust anchors are initialized from:
				Initialize-DnssecTrustAnchorFile.ps1

		Users may override trust anchors using:
				Add-DnssecTrustAnchor
				Import-DnssecTrustAnchorFile
				Update-DnssecTrustAnchorFile

		Trust anchors are stored in module-scope variables and used by:
				Resolve-Dnssec
				Resolve-DnssecChain
				Test-DnssecValidation
				Test-DnssecAnchoredDnskey

		# ---------------------------------------------------------------------------
		# MODULE STRUCTURE OVERVIEW
		# ---------------------------------------------------------------------------

		Exported Functions:
				- DNS iterative resolution
				- DNSSEC validation and chain traversal
				- Trust anchor management
				- Type/class/algorithm conversion utilities
				- Wire-format packet parsing and UDP query generation

		Internal Functions:
				- Canonicalization helpers
				- NSEC/NSEC3 logic
				- Signature validation
				- Wire-format encoding/decoding
				- Transport safety wrappers
				- Trace and formatting helpers

		Maps:
				- QtypeMap - DNS RR type <-> code mapping
				- TypeCoveredMap - RRSIG type-covered mapping
				- DnsClassMap - DNS class <-> code mapping
				- DnssecAlgorithmMap - DNSSEC algorithm codes
				- DnssecDigestMap - DS digest algorithms
				- EdnsOptionMap - EDNS option codes
				- RcodeMap - DNS response codes
				- DnsOpCodeMap - DNS operation codes
				- TLSA, SSHFP, NSEC3 maps - protocol-specific constants

		# ---------------------------------------------------------------------------
		# MAINTENANCE NOTES
		# ---------------------------------------------------------------------------

		- If FunctionExportTable is modified, regenerate DnsTools.psm1.
		- Ordering of maps is intentional; do not reorder unless updating RFCs.
		- Deprecated RR types remain in maps for completeness and RRSIG coverage.
		- This module is designed for PowerShell 7+ compatibility.
		- All changes should preserve deterministic behavior and reproducibility.

#>
# =============================================================================
# FUNCTION EXPORT CONTROL
# =============================================================================
# This table defines which functions are exported (public API) and which remain
# internal to the module. Ordering is intentional and preserved.
#
# Exported functions form the user-facing DNS/DNSSEC toolkit.
# Internal functions support canonicalization, wire-format parsing, DNSSEC
# validation, and transport safety.
#
# NOTE:
#   If this table is modified, regenerate DnsTools.psm1 and redeploy.
# =============================================================================

$script:FunctionExportTable = @{

	# -------------------------------------------------------------------------
	# PUBLIC DNS RESOLUTION FUNCTIONS
	# -------------------------------------------------------------------------

	'Resolve-DnsIterative' = $true
	# Performs full iterative DNS resolution from the root downward.
	# Uses: RootServerAddresses, QtypeMap, DnsClassMap.
	# Public entry point for non-DNSSEC resolution.

	'Resolve-Dnssec' = $true
	# Performs DNSSEC-aware resolution.
	# Validates signatures, DS/DNSKEY chains, and negative proofs.
	# Uses: Resolve-DnsIterative, Test-DnssecValidation, RRSIG/NSEC/NSEC3 logic.

	'Resolve-DnssecChain' = $true
	# Returns the full DNSSEC chain of trust for a name.
	# Useful for debugging and forensic analysis.
	# Uses: DnssecAlgorithmMap, DnssecDigestMap, TypeCoveredMap.

	'Resolve-DnssecName' = $true
	# High-level wrapper for resolving a single name with DNSSEC validation.
	# Combines resolution + chain validation + formatting.

	'Test-DnssecValidation' = $true
	# Validates an entire DNSSEC response set.
	# Uses: Test-DnssecRrsig, Test-DnssecDsForDnskey, Test-DnssecAnchoredDnskey.

	'Test-DnssecName' = $true
	# Validates DNSSEC for a specific name.
	# Useful for automated testing and CI pipelines.

	'Update-DnssecTrustAnchorFile' = $true
	# Refreshes trust anchors (e.g., root KSK rollover).
	# Uses: TrustAnchorsInitialized.

	'Get-DnssecTrustAnchorStore' = $true
	# Returns currently loaded trust anchors.

	'Add-DnssecTrustAnchor' = $true
	# Adds a new trust anchor (DS or DNSKEY).
	# Supports custom validation environments.

	'Import-DnssecTrustAnchorFile' = $true
	# Imports trust anchors from file or external source.


	# -------------------------------------------------------------------------
	# PUBLIC ROOT HINTS MANAGEMENT
	# -------------------------------------------------------------------------

	'Update-DnsRootHintsFile' = $true
	# Persists the verified root hints captured this session to the protected baseline (elevates once).


	# -------------------------------------------------------------------------
	# PUBLIC TYPE/CLASS/ALGORITHM CONVERSION UTILITIES
	# -------------------------------------------------------------------------

	'ConvertTo-DnsTypeCode' = $true
	# Converts RR type name -> numeric code using QtypeMap.

	'ConvertFrom-DnsTypeCode' = $true
	# Converts numeric RR type code -> name using QtypeMap.

	'Format-DnsTypeName' = $true
	# Normalizes RR type names for display and logging.

	'ConvertTo-DnsClassCode' = $true
	# Converts DNS class name -> numeric code.

	'ConvertFrom-DnsClassCode' = $true
	# Converts numeric DNS class code -> name.

	'Format-DnsClassName' = $true
	# Normalizes class names for display.

	'ConvertTo-DnssecAlgorithmCode' = $true
	# Converts DNSSEC algorithm name -> numeric code using DnssecAlgorithmMap.

	'ConvertFrom-DnssecAlgorithmCode' = $true
	# Converts numeric DNSSEC algorithm code -> name.

	'Format-DnssecAlgorithmName' = $true
	# Normalizes algorithm names for display.


	# -------------------------------------------------------------------------
	# PUBLIC WIRE-FORMAT UTILITIES
	# -------------------------------------------------------------------------

	'ConvertFrom-DnsPacket' = $true
	# Parses raw DNS wire bytes into structured objects.
	# Uses: ConvertFrom-DnsHeader, ConvertFrom-DnsQuestion, ConvertFrom-DnsWireBuffer.

	'New-DnsQueryPacket' = $true
	# Constructs a DNS query packet in canonical wire format.

	'Invoke-DnsUdpQuery' = $true
	# Sends a DNS query via UDP with transport safety checks.
	# Uses: Invoke-DnsTransportSafe.


	# -------------------------------------------------------------------------
	# INTERNAL FUNCTIONS - NOT EXPORTED
	# -------------------------------------------------------------------------
	# These functions implement the core mechanics of DNSSEC, canonicalization,
	# wire-format parsing, and transport safety. They are intentionally internal
	# to prevent accidental misuse and to maintain a clean public API.

	# 'Write-Trace' entry removed 2026-09-15 - Functions\Write-Trace.ps1 retired (replaced by the
	# vendored Write-MyFunctionTrace facility; -Message-style calls elsewhere became Write-Verbose).

	'Resolve-NameserverAddress' = $false
	# Normalizes nameserver input (IPv4/IPv6/hostname).

	'Invoke-DnsTransportSafe' = $false
	# Wraps UDP transport with retry and timeout logic.

	'ConvertFrom-DnsWireBuffer' = $false
	# Converts raw wire bytes into structured RR objects.

	'ConvertTo-DnsWireBuffer' = $false
	# Serializes DNS objects into canonical wire format.

	'ConvertTo-HexString' = $false
	# Utility for hex encoding.

	'ConvertFrom-DnsHeader' = $false
	# Parses DNS header fields.

	'ConvertFrom-DnsQuestion' = $false
	# Parses DNS question section.

	'Get-RecordTypeA' = $false
	# Internal handler for A records.

	'Get-RecordTypeAAAA' = $false
	# Internal handler for AAAA records.

	'Format-DnsIterativeResult' = $false
	# Formats iterative resolution output.

	'Format-DnsResponse' = $false
	# Formats DNS response objects.

	'Format-DnssecResult' = $false
	# Formats DNSSEC validation results.

	'Initialize-DnssecTrustAnchorFile' = $false
	# Loads trust anchors at module initialization.

	'Invoke-RootHintsBaselineOffer' = $false
	# Module-init helper: offers to persist verified root hints when they differ from the baseline.
	# Auto-invoked once at import; NOT public (exporting it would let users re-trigger the elevating offer).


	# -------------------------------------------------------------------------
	# INTERNAL DNSSEC FUNCTIONS - NOT EXPORTED
	# -------------------------------------------------------------------------
	# These functions implement the core DNSSEC validation pipeline.

	'Get-DnssecCanonicalNameWire' = $false
	# Canonicalizes DNS names for signature validation.

	'Get-DnssecCanonicalRrWire' = $false
	# Canonicalizes RR wire format for RRSIG validation.

	'Get-DnssecCanonicalRrsetData' = $false
	# Extracts canonical RRset data for signature hashing.

	'Get-DnssecSignedData' = $false
	# Builds the signed data blob for RRSIG verification.

	'Get-DnssecKeyDigest' = $false
	# Computes DS digest from DNSKEY.

	'Get-DnssecKeyDigestHex' = $false
	# Hex-encoded DS digest.

	'Get-DnssecNsec3Hash' = $false
	# Computes NSEC3 hash for closest-encloser logic.

	'Get-DnssecSigningKey' = $false
	# Selects the correct DNSKEY for an RRSIG.

	'Test-DnssecTimeWindow' = $false
	# Validates RRSIG inception/expiration windows.

	'Test-DnssecRrsig' = $false
	# Validates RRSIG over an RRset.

	'Test-DnssecDsForDnskey' = $false
	# Validates DS <-> DNSKEY relationship.

	'Get-DnssecZonePath' = $false
	# 2026-09-15: splits a name into its root->leaf zone list for Resolve-DnssecChain's walk.

	'Get-RootTrustAnchor' = $false
	# 2026-09-15: returns the configured trust anchor(s) for zone '.'.

	'Resolve-DnssecZone' = $false
	# 2026-09-15: validates one zone's DS/DNSKEY/RRSIG chain for Resolve-DnssecChain's per-zone walk.

	'Test-DnssecChain' = $false
	# Validates full DNSSEC chain of trust.

	'Test-DnsZoneApex' = $false
	# 0.8: true when a name owns its own SOA (a zone apex); used to build the zone path (internal).

	'Get-DnssecTrustedKey' = $false
	# 0.8: authenticates a zone's DNSKEY RRset up the chain to a configured trust anchor (internal).

	'Get-DnssecDsMatchedKey' = $false
	# 0.8: returns the DNSKEYs a DS RRset authenticates (internal).

	'Test-DnssecRrsetSignature' = $false
	# 0.8: an RRset has a valid RRSIG from a trusted key, signer checked (internal).

	'Test-DnssecResponseSignature' = $false
	# 0.8: validates every answer RRset against authenticated keys (internal; used by Resolve-DnsIterative -ValidateDnssec and Resolve-Dnssec).

	'Test-DnssecNsec3Nodata' = $false
	# Validates NSEC3-based NODATA proofs.

	'Test-DnssecNsec3Nxdomain' = $false
	# Validates NSEC3-based NXDOMAIN proofs.

	'Test-DnssecNsec3OptOut' = $false
	# Validates NSEC3 Opt-Out behavior.

	'Find-DnssecNsec3ClosestEncloser' = $false
	# Finds closest encloser for NSEC3 proofs.

	'Find-DnssecNsec3NextCloser' = $false
	# Computes next-closer name for NSEC3 proofs.

	'Test-DnssecAnchoredDnskey' = $false
	# Validates DNSKEY against trust anchors.

	'Test-DnssecSignature' = $false
	# Performs cryptographic signature validation.

	'ConvertTo-ReverseDnsName' = $false
	# Converts IP addresses to reverse-DNS names.
}
# =============================================================================
# VARIABLE DEFINITIONS AND MODULE-LEVEL STATE
# =============================================================================
# These blocks define constant, read-only, and mutable variables used throughout
# the module. Ordering is intentional and preserved.
#
# Variable groups:
#   - N00ConstantVars   - Script-scope constants (immutable)
#   - N01ReadOnlyVars   - Script-scope read-only values
#   - N02ReadOnlyVars   - Environment and module metadata
#   - N03OtherVars      - Mutable runtime state (logging, console, etc.)
#   - N09Finalise       - Final initialization (root hints, maps, trust anchors)
#
# NOTE:
#   Constants cannot be reloaded without restarting PowerShell.
#   Read-only variables enforce module integrity.
#   Mutable variables support runtime behavior (logging, tracing, etc.).
# =============================================================================


# -------------------------------------------------------------------------
# CONSTANT VARIABLES (IMMUTABLE)
# -------------------------------------------------------------------------
# These values define the constant semantics used throughout the module.
# They are script-scope and read-only to prevent accidental modification.
# -------------------------------------------------------------------------

$MyVars = [Ordered]@{
	N00ConstantVars = @{
		VOConstant = @{
			Value  = 'Constant'
			Scope  = 'Script'
			Option = 'ReadOnly'
		}
		VSScript = @{
			Value  = 'Script'
			Scope  = 'Script'
			Option = 'ReadOnly'
		}
		VOReadOnly = @{
			Value  = 'ReadOnly'
			Scope  = 'Script'
			Option = 'ReadOnly'
		}
	}
}
Publish-Variable -Variables $MyVars


# -------------------------------------------------------------------------
# CONSTANT FLAGS FOR INFORMATION OUTPUT
# -------------------------------------------------------------------------
# These flags control optional informational output for:
#   - Variables
#   - Common functions
#   - OS-specific functions (Windows/Linux/Mac)
# They are read-only to ensure consistent behavior.
# -------------------------------------------------------------------------

$MyVars = [Ordered]@{
	N00ConstantVars = @{
		VInfoOn = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VOReadOnly
			Use    = 'Define Variables Information'
		}
		FInfoOn = @{
			Value  = $false
			Scope  = $VSScript
			Option = $VOReadOnly
			Use    = 'Define Common Functions Information'
		}
		FWInfoOn = @{
			Value  = $false
			Scope  = $VSScript
			Option = $VOReadOnly
			Use    = 'Define Windows Functions Information'
		}
		FLInfoOn = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VOReadOnly
			Use    = 'Define Linux Functions Information'
		}
		FMInfoOn = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VOReadOnly
			Use    = 'Define MacOS Functions Information'
		}
	}
}
Publish-Variable -Variables $MyVars


# -------------------------------------------------------------------------
# READ-ONLY VARIABLES (SCOPE & OPTION CONSTANTS)
# -------------------------------------------------------------------------
# These define the allowed scopes and variable options used throughout the
# module. They are read-only to prevent accidental mutation.
# -------------------------------------------------------------------------

$MyVars = @{
	N01ReadOnlyVars = @{
		VSGlobal = @{
			Value  = 'Global'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VSUsing = @{
			Value  = 'Using'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VSWorkFlow = @{
			Value  = 'WorkFlow'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VOAllScope = @{
			Value  = 'AllScope'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VOPrivate = @{
			Value  = 'Private'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		VONone = @{
			Value  = 'None'
			Scope  = $VSScript
			Option = $VOReadOnly
		}
	}
}
Publish-Variable -Variables $MyVars


# -------------------------------------------------------------------------
# MODULE METADATA AND ENVIRONMENT INFORMATION
# -------------------------------------------------------------------------
# These values describe the module version, PowerShell version, culture,
# environment, and runtime context. They are read-only except where noted.
# -------------------------------------------------------------------------

$ML = @{
	Name = $ModuleName
	Path = $ModuleScriptRoot
}

$MyVars = @{
	N02ReadOnlyVars = @{
		ModuleVersion = @{
			Value  = $PSD1Data.ModuleVersion
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		MajorPSVersion = @{
			Value  = [String]($PSVersionTable.PSVersion.Major)
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		ModuleLoaded = @{
			Value  = $ML
			Scope  = $VSScript
			Option = $VONone
		}
		Administrator = @{
			Value  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		Interactive = @{
			Value  = [Environment]::UserInteractive
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		MyCulture = @{
			Value  = [cultureinfo]::GetCultures('Allcultures') |
				Where-Object -Property name -imatch (Get-Culture).name
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrCRLF = @{
			Value  = "`r`n"
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrCR = @{
			Value  = "`r"
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		StrLF = @{
			Value  = "`n"
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		DayOfWeek = @{
			Value  = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([Ordered]@{
					Monday    = 1; Tuesday   = 2; Wednesday = 3; Thursday  = 4
					Friday    = 5; Saturday  = 6; Sunday    = 7
				})
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		MonthOfYear = @{
			Value  = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ( [Ordered]@{
					January   = 1; February  = 2; March     = 3; April     = 4
					May       = 5; June      = 6; July      = 7; August    = 8
					September = 9; October   = 10; November = 11; December = 12
				})
			Scope  = $VSScript
			Option = $VOReadOnly
		}
	}
}
Publish-Variable -Variables $MyVars


# -------------------------------------------------------------------------
# MUTABLE RUNTIME VARIABLES
# -------------------------------------------------------------------------
# These values control logging, tracing, console behavior, file rotation,
# and runtime state. They are intentionally mutable.
# -------------------------------------------------------------------------

$MyVars = @{
	N03OtherVars = @{
		LogFilePath = @{
			Value  = $Null
			Scope  = $VSScript
			Option = $VONone
		}
		LogLevel = @{
			Value  = 0
			Scope  = $VSScript
			Option = $VONone
		}
		LogLevelSave = @{
			Value  = 0
			Scope  = $VSScript
			Option = $VONone
		}
		MaxLogLevel = @{
			Value  = 5
			Scope  = $VSScript
			Option = $VOReadOnly
		}
		LogLinePad = @{
			Value  = 5
			Scope  = $VSScript
			Option = $VONone
		}
		KeepCopies = @{
			Value  = 5
			Scope  = $VSScript
			Option = $VONone
		}
		FileSize = @{
			Value  = 100KB
			Scope  = $VSScript
			Option = $VONone
		}
		FileNumber = @{
			Value  = 10
			Scope  = $VSScript
			Option = $VONone
		}
		FileDays = @{
			Value  = 10
			Scope  = $VSScript
			Option = $VONone
		}
		Console = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VONone
		}
		EnCoding = @{
			Value  = 'UTF8'
			Scope  = $VSScript
			Option = $VONone
		}
		WindowHeight = @{
			Value  = 0
			Scope  = $VSScript
			Option = $VONone
		}
		WindowWidth = @{
			Value  = 0
			Scope  = $VSScript
			Option = $VONone
		}
		IsConsole = @{
			Value  = $False
			Scope  = $VSScript
			Option = $VONone
		}
		# 2026-09-15: MyInitialCallStack/MyInitialCallingScript/FTraceInternalCall/FTraceAllCalls/
		# FTLogFilPath/FTrace REMOVED - dead declarations (confirmed zero other references anywhere in
		# this module) from the retired $Script:FTrace facility, replaced by the vendored
		# Write-MyFunctionTrace/Enable-/Disable-MyFunctionTrace family,
		# toggled via $env:MyFunctionTraceEnabled instead of a module-scope variable
		# so it also reaches a NamedPipe-elevated child process.
		StrContinue = @{
			Value  = 'Continue'
			Scope  = $VSScript
			Option = $VONone
		}
		StrSilentlyContinue = @{
			Value  = 'SilentlyContinue'
			Scope  = $VSScript
			Option = $VONone
		}
		StrInquire = @{
			Value  = 'Inquire'
			Scope  = $VSScript
			Option = $VONone
		}
		StrStop = @{
			Value  = 'Stop'
			Scope  = $VSScript
			Option = $VONone
		}
		StrVerbose = @{
			Value  = 'Verbose'
			Scope  = $VSScript
			Option = $VONone
		}
		StrExtPS1 = @{
			Value  = '.ps1'
			Scope  = $VSScript
			Option = $VONone
		}
		StrExtZip = @{
			Value  = '.zip'
			Scope  = $VSScript
			Option = $VONone
		}
	}
}
Publish-Variable -Variables $MyVars
# =============================================================================
# DNS TYPE / CLASS / ALGORITHM / OPTION MAPS
# =============================================================================
# These maps define the numeric codes used throughout DNS and DNSSEC. They are
# used by:
#   - ConvertTo-DnsTypeCode / ConvertFrom-DnsTypeCode
#   - ConvertTo-DnsClassCode / ConvertFrom-DnsClassCode
#   - DNSSEC canonicalization and signature validation
#   - RRSIG TypeCovered logic
#   - Packet parsing and construction
#
# Deprecated RR types remain present for:
#   - RRSIG TypeCovered correctness
#   - Historical packet parsing
#   - Forensic analysis
#
# Ordering is intentional and preserved.
# =============================================================================


# -------------------------------------------------------------------------
# ROOT SERVER ADDRESSES
# -------------------------------------------------------------------------
# Loaded from Helpers\Get-RootHints.ps1.
# Used by Resolve-DnsIterative and Resolve-Dnssec.
# -------------------------------------------------------------------------
$MyVars = @{
	N07DNS = @{

		# -------------------------------------------------------------------------
		# QTYPE MAP - DNS RR TYPE <-> CODE
		# -------------------------------------------------------------------------
		# This is the authoritative mapping of DNS record types to numeric codes.
		# Used by:
		#   - ConvertTo-DnsTypeCode
		#   - ConvertFrom-DnsTypeCode
		#   - Packet parsing
		#   - RRSIG TypeCovered logic
		#
		# Deprecation notes and replacements included inline.
		# -------------------------------------------------------------------------

		QtypeMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{

					# --- Core DNS Types ---------------------------------------------------
					A          = 1
					NS         = 2
					CNAME      = 5
					SOA        = 6

					WKS        = 11   # Legacy, rarely used; retained for completeness.

					PTR        = 12
					HINFO      = 13   # Deprecated - privacy risk. Replacement: do not publish.
					MX         = 15
					TXT        = 16
					RP         = 17   # Deprecated - use WHOIS/HTTPS contact pages.
					AFSDB      = 18   # Deprecated - AFS ecosystem obsolete.
					LOC        = 29   # Discouraged - privacy concerns.

					AAAA       = 28
					SRV        = 33
					NAPTR      = 35   # Rare - mostly ENUM.
					DNAME      = 39

					# --- DNSSEC Types -----------------------------------------------------
					DS         = 43
					SSHFP      = 44
					IPSECKEY   = 45    # IPsec keying material (RFC 4025).
					RRSIG      = 46
					NSEC       = 47
					DNSKEY     = 48
					NSEC3      = 50
					NSEC3PARAM = 51
					TLSA       = 52
					SMIMEA     = 53
					CDS        = 59    # Child DS
					CDNSKEY    = 60    # Child DNSKEY
					OPENPGPKEY = 61    # OpenPGP public key (RFC 7929).

					# --- Service Binding --------------------------------------------------
					SVCB       = 64
					HTTPS      = 65

					# --- Deprecated / Legacy ---------------------------------------------
					SPF        = 99    # Deprecated - RFC 7208. Replacement: TXT.
					# --- Transaction/Transfer --------------------------------------------
					TKEY       = 249   # Deprecated - replaced by TSIG.
					TSIG       = 250   # Transaction signature
					IXFR       = 251   # Incremental zone transfer
					AXFR       = 252   # Full zone transfer
					ANY        = 255   # Request all types
					URI        = 256   # Uniform Resource Identifier
					CAA        = 257
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# DNS CLASS MAP - CLASS <-> CODE
		# -------------------------------------------------------------------------
		# Used by:
		#   - ConvertTo-DnsClassCode
		#   - ConvertFrom-DnsClassCode
		#   - Packet parsing
		# -------------------------------------------------------------------------

		DnsClassMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					IN   = 1
					CS   = 2
					CH   = 3
					HS   = 4
					NONE = 254
					ANY  = 255
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# DNSSEC ALGORITHM MAP - ALGORITHM <-> CODE
		# -------------------------------------------------------------------------
		# Used by:
		#   - Test-DnssecSignature
		#   - Test-DnssecRrsig
		#   - ConvertTo-DnssecAlgorithmCode
		#   - ConvertFrom-DnssecAlgorithmCode
		#
		# Deprecated algorithms remain for historical validation.
		# -------------------------------------------------------------------------

		DnssecAlgorithmMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					RSAMD5             = 1     # Deprecated - insecure.
					DH                 = 2     # Deprecated.
					DSA                = 3     # Deprecated.
					ECC                = 4     # Legacy.
					RSASHA1            = 5     # Deprecated - SHA-1 collision risk.
					DSA_NSEC3_SHA1     = 6     # Deprecated.
					RSASHA1_NSEC3_SHA1 = 7     # Deprecated.
					RSASHA256          = 8     # Common.
					RSASHA512          = 10    # Common.
					ECC_GOST           = 12    # Rare.
					ECDSAP256SHA256    = 13    # Recommended.
					ECDSAP384SHA384    = 14    # Recommended.
					ED25519            = 15    # Modern, recommended.
					ED448              = 16    # Modern.
					INDIRECT           = 252
					PRIVATEDNS         = 253
					PRIVATEOID         = 254
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# DNSSEC DIGEST MAP - DS DIGEST ALGORITHMS
		# -------------------------------------------------------------------------
		# Used by:
		#   - Test-DnssecDsForDnskey
		#   - DS record validation
		# -------------------------------------------------------------------------

		DnssecDigestMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					SHA1   = 1   # Deprecated - SHA-1 collision risk.
					SHA256 = 2   # Recommended.
					GOST   = 3   # Rare.
					SHA384 = 4   # Recommended.
				})
			Scope  = $VSScript
			Option = $VONone
		}

		# -------------------------------------------------------------------------
		# RCODE MAP - DNS RESPONSE CODES
		# -------------------------------------------------------------------------
		# Used by:
		#   - ConvertFrom-DnsHeader
		#   - Error handling
		# -------------------------------------------------------------------------

		RcodeMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					NoError          = 0
					FormErr          = 1
					ServFail         = 2
					NXDomain         = 3
					NotImp           = 4
					Refused          = 5
					YXDomain         = 6
					YXRRSet          = 7
					NXRRSet          = 8
					NotAuth          = 9
					NotZone          = 10
					BADVERS_BADSIG   = 16
					BADKEY           = 17
					BADTIME          = 18
					BADMODE          = 19
					BADNAME          = 20
					BADALG           = 21
					BADTRUNC         = 22
					BADCOOKIE        = 23
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# TYPE COVERED MAP - RRSIG TYPE-COVERED FIELD
		# -------------------------------------------------------------------------
		# Used by:
		#   - Test-DnssecRrsig
		#   - Canonical RRset validation
		#
		# Deprecated types remain for historical RRSIG validation.
		# -------------------------------------------------------------------------

		TypeCoveredMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					A          = 1
					NS         = 2
					CNAME      = 5
					SOA        = 6
					WKS        = 11
					PTR        = 12
					HINFO      = 13    # Deprecated.
					MX         = 15
					TXT        = 16
					RP         = 17    # Deprecated.
					AFSDB      = 18    # Deprecated.
					AAAA       = 28
					LOC        = 29    # Discouraged.
					SRV        = 33
					NAPTR      = 35
					DNAME      = 39
					DS         = 43
					SSHFP      = 44
					IPSECKEY   = 45
					RRSIG      = 46
					NSEC       = 47
					DNSKEY     = 48
					NSEC3      = 50
					NSEC3PARAM = 51
					TLSA       = 52
					SMIMEA     = 53
					CDS        = 59
					CDNSKEY    = 60
					OPENPGPKEY = 61
					SVCB       = 64
					HTTPS      = 65
					SPF        = 99    # Deprecated - TXT replacement.
					TKEY       = 249   # Deprecated - TSIG replacement.
					TSIG       = 250
					IXFR       = 251
					AXFR       = 252
					ANY        = 255
					URI        = 256
					CAA        = 257
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# EDNS OPTION MAP - EDNS0 OPTION CODES
		# -------------------------------------------------------------------------
		# Used by:
		#   - OPT pseudo-record parsing
		#   - EDNS client subnet, padding, cookies, etc.
		# -------------------------------------------------------------------------

		EdnsOptionMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					0     = 'Reserved'
					1     = 'LLQ'
					2     = 'UL'
					3     = 'NSID'
					4     = 'DAU'
					5     = 'DHU'
					6     = 'N3U'
					7     = 'ClientSubnet'
					8     = 'Expire'
					9     = 'Cookie'
					10    = 'TcpKeepalive'
					11    = 'Padding'
					12    = 'Chain'
					13    = 'EdnsKeyTag'
					14    = 'ExtendedDnsError'
					15    = 'EdnsClientTag'
					16    = 'EdnsServerTag'
					26946 = 'DeviceID'
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# DNS HEADER FLAGS MAP - BITMASKS
		# -------------------------------------------------------------------------
		# Used by:
		#   - ConvertFrom-DnsHeader
		#   - Response interpretation
		# -------------------------------------------------------------------------

		DnsHeaderFlagsMap = @{
			Value = [ordered]@{
				QR = 0x8000  # Query/Response
				AA = 0x0400  # Authoritative Answer
				TC = 0x0200  # Truncated
				RD = 0x0100  # Recursion Desired
				RA = 0x0080  # Recursion Available
				Z  = 0x0040  # Reserved (must be zero)
				AD = 0x0020  # Authenticated Data (DNSSEC)
				CD = 0x0010  # Checking Disabled (DNSSEC)
			}
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# DNS OPCODE MAP - OPERATION CODES
		# -------------------------------------------------------------------------

		DnsOpCodeMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					QUERY  = 0
					IQUERY = 1
					STATUS = 2
					NOTIFY = 4
					UPDATE = 5
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# DNSKEY FLAGS MAP - BITMASKS FOR KSK/ZSK/REVOKE
		# -------------------------------------------------------------------------

		DnsKeyFlagsMap = @{
			Value = [ordered]@{
				ZONE   = 0x0100  # Zone Key flag (bit 7)
				REVOKE = 0x0080  # Revoke flag (bit 8)
				SEP    = 0x0001  # Secure Entry Point (bit 15) - indicates KSK
			}
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# NSEC3 FLAGS MAP - BITMASKS
		# -------------------------------------------------------------------------

		Nsec3FlagsMap = @{
			Value = [ordered]@{
				OptOut = 0x01
			}
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# TLSA USAGE MAP - CERTIFICATE USAGE FIELD
		# -------------------------------------------------------------------------

		TlsaUsageMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					PKIX_TA = 0  # CA constraint
					PKIX_EE = 1  # Service certificate constraint
					DANE_TA = 2  # Trust anchor assertion
					DANE_EE = 3  # Domain-issued certificate
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# TLSA SELECTOR MAP - CERTIFICATE SELECTOR FIELD
		# -------------------------------------------------------------------------

		TlsaSelectorMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					FullCert = 0  # Full certificate
					SPKI     = 1  # SubjectPublicKeyInfo
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# TLSA MATCHING TYPE MAP - HASH TYPE
		# -------------------------------------------------------------------------

		TlsaMatchingTypeMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					Exact  = 0
					SHA256 = 1
					SHA512 = 2
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# SSHFP ALGORITHM MAP
		# -------------------------------------------------------------------------

		SshfpAlgorithmMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					RSA     = 1
					DSA     = 2
					ECDSA   = 3
					ED25519 = 4
					ED448   = 6
				})
			Scope  = $VSScript
			Option = $VONone
		}


		# -------------------------------------------------------------------------
		# SSHFP FINGERPRINT TYPE MAP
		# -------------------------------------------------------------------------

		SshfpFingerprintTypeMap = @{
			Value = . (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Add-ReverseMapEntries.ps1') -Map ([ordered]@{
					SHA1   = 1   # Deprecated - SHA-1 collision risk.
					SHA256 = 2   # Recommended.
				})
			Scope  = $VSScript
			Option = $VONone
		}
	}
}
Publish-Variable -Variables $MyVars

# =============================================================================
# FINAL INITIALIZATION BLOCK
# =============================================================================
# This block performs the final module-level initialization steps:
#
#   - Load root server hints
#   - Initialize DNSSEC trust anchors
#   - Publish all variable groups
#   - Mark the module as fully initialized
#
# These steps must occur *after* all maps, variables, and helper functions
# have been defined, because DNSSEC validation depends on:
#   - QtypeMap
#   - DnsClassMap
#   - DnssecAlgorithmMap
#   - DnssecDigestMap
#   - TypeCoveredMap
#   - NSEC/NSEC3 maps
#
# Ordering is intentional and preserved.
# =============================================================================

$MyVars = @{
	N09Finalise = @{
		# -------------------------------------------------------------------------
		# INITIALIZE ROOT HINTS
		# -------------------------------------------------------------------------
		# Root hints are loaded earlier into RootServerAddresses via:
		#   Helpers\Get-RootHints.ps1
		#
		# They are used by:
		#   - Resolve-DnsIterative
		#   - Resolve-Dnssec
		#
		# Users may override root hints by modifying RootServerAddresses.Value.
		# -------------------------------------------------------------------------
		RootServerAddresses = @{
			Value  = ( (. (Join-Path -Path $ModuleScriptRoot -ChildPath 'Helpers\Get-RootHints.ps1')).RootServerAddresses )
			Scope  = $VSScript
			Option = $VONone
		}
		# -------------------------------------------------------------------------
		# INITIALIZE DNSSEC TRUST ANCHORS
		# -------------------------------------------------------------------------
		# Trust anchors are loaded from:
		#   Initialize-DnssecTrustAnchorFile.ps1
		#
		# They are used by:
		#   - Resolve-Dnssec
		#   - Resolve-DnssecChain
		#   - Test-DnssecAnchoredDnskey
		#   - Test-DnssecValidation
		#
		# Users may override trust anchors via:
		#   - Add-DnssecTrustAnchor
		#   - Import-DnssecTrustAnchorFile
		#   - Update-DnssecTrustAnchorFile
		#
		# Trust anchors are stored in script-scope variables for deterministic behavior.
		# -------------------------------------------------------------------------

		TrustAnchorsInitialized = @{
			Value  = ( . (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-DnssecTrustAnchorFile.ps1') )
			Scope  = $VSScript
			Option = $VONone
		}

	}}
Publish-Variable -Variables $MyVars


# -------------------------------------------------------------------------
# MODULE READY FLAG
# -------------------------------------------------------------------------
# Indicates that:
#   - All maps are loaded
#   - All variables are published
#   - Root hints are available
#   - Trust anchors are initialized
#
# This flag is used by:
#   - Resolve-Dnssec
#   - Test-DnssecValidation
#   - Any function requiring DNSSEC readiness
# -------------------------------------------------------------------------

$script:ModuleInitialized = $true
