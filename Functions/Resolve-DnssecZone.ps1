function Resolve-DnssecZone
{
	<#
		.SYNOPSIS
		Validates one zone's DNSSEC chain of trust: fetches its DS and DNSKEY records and confirms the
		DNSKEY RRset is both DS-matched and correctly self-signed.

		.DESCRIPTION
		2026-09-15. Written to fill a real gap: Resolve-DnssecChain.ps1 already called this function by
		name (once per zone in its walk from root to leaf), but it had never been implemented anywhere
		in the module (confirmed via a repo-wide grep - zero definitions, including in the retired
		0.5/0.6 copies of Resolve-DnssecChain.ps1, which have the identical call - this has been an
		unfinished stub since at least 0.5).

		This is an extraction of the per-zone validation body Test-DnssecValidation.ps1 already performs
		inline in its own zone-walk loop (query DS, query DNSKEY+RRSIG, match DS->DNSKEY via
		Test-DnssecDsForDnskey, validate each RRSIG via Test-DnssecTimeWindow/Get-DnssecSigningKey/
		Get-DnssecSignedData/Test-DnssecSignature) into a reusable function that returns a clean
		Valid/Reason/Dnskeys object instead of writing report entries - the same relationship
		Resolve-Dnssec already has to its own inline validation logic.

		Queries DS and DNSKEY directly at $Zone's own name - the iterative resolver (Resolve-DnsIterative)
		already walks to the correct authoritative server for each query, so $ParentZone is used only for
		diagnostic Reason text, not as a query target (matching Test-DnssecValidation's own messaging:
		"Querying DS records for $childZone from parent zone $parentZone").

		Does NOT cryptographically verify the DS RRset's own RRSIG against the parent's DNSKEY - it
		matches the DS digest against the child's live DNSKEY RRset only, exactly like
		Test-DnssecValidation.ps1's existing (already-accepted) implementation. A caller that walks
		multiple zones therefore trusts DNS's own routing to the right authoritative server rather than
		a cryptographically linked delegation at every hop - a known simplification already established
		elsewhere in this module, not introduced here.

		.PARAMETER Zone
		The zone to validate (absolute name, e.g. 'com.', 'cloudflare.com.').

		.PARAMETER ParentZone
		The parent zone name, used only for diagnostic messages.

		.PARAMETER RootServers
		Array of root server IP addresses to use for resolution (defaults to module-configured root servers).

		.PARAMETER Trace
		Enable verbose trace output for debugging DNS resolution.

		.OUTPUTS
		[PSCustomObject] with Valid ([bool]), Reason ([string]), Dnskeys (the zone's DNSKEY resource
		records, or an empty array on failure).

		.EXAMPLE
		Resolve-DnssecZone -Zone 'com.' -ParentZone '.'
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	Param (
		[Parameter(Mandatory)]
		[string]$Zone,

		[Parameter(Mandatory)]
		[string]$ParentZone,

		[string[]]$RootServers = $script:RootServerAddresses,

		[switch]$Trace
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try {
		Write-Verbose -Message "Querying DS records for $Zone from parent zone $ParentZone"
		$dsResult = Resolve-DnsIterative -Name $Zone -Type 43 -RootServers $RootServers -Trace:$Trace -Raw
		if ($dsResult.Status -ne 'Final') {
			return [PSCustomObject]@{
				Valid   = $false
				Reason  = "DS query for $Zone failed: $($dsResult.Reason)"
				Dnskeys = @()
			}
		}
		$Private:DsRecords = @($dsResult.Response.Answers | Where-Object -FilterScript { $_.Type -eq 43 })

		Write-Verbose -Message "Querying DNSKEY records for $Zone"
		$dnskeyResult = Resolve-DnsIterative -Name $Zone -Type 48 -RootServers $RootServers -Trace:$Trace -Raw
		if ($dnskeyResult.Status -ne 'Final') {
			return [PSCustomObject]@{
				Valid   = $false
				Reason  = "DNSKEY query for $Zone failed: $($dnskeyResult.Reason)"
				Dnskeys = @()
			}
		}
		$Private:DnskeyRecords = @($dnskeyResult.Response.Answers | Where-Object -FilterScript { $_.Type -eq 48 })
		$Private:RrsigRecords  = @($dnskeyResult.Response.Answers | Where-Object -FilterScript { $_.Type -eq 46 })

		if ($Private:DsRecords.Count -eq 0) {
			return [PSCustomObject]@{
				Valid   = $false
				Reason  = "No DS records found for $Zone - zone may be unsigned"
				Dnskeys = $Private:DnskeyRecords
			}
		}
		if ($Private:DnskeyRecords.Count -eq 0) {
			return [PSCustomObject]@{
				Valid   = $false
				Reason  = "No DNSKEY records found for $Zone"
				Dnskeys = @()
			}
		}

		$Private:DsValidation = Test-DnssecDsForDnskey -DsRrset $Private:DsRecords -DnskeyRrset $Private:DnskeyRecords -ChildZoneName $Zone
		$Private:MatchedDs = @($Private:DsValidation | Where-Object -FilterScript { $_.Valid })
		if ($Private:MatchedDs.Count -eq 0) {
			return [PSCustomObject]@{
				Valid   = $false
				Reason  = "DS records for $Zone did not match any DNSKEY (secure delegation failure)"
				Dnskeys = $Private:DnskeyRecords
			}
		}

		if ($Private:RrsigRecords.Count -eq 0) {
			return [PSCustomObject]@{
				Valid   = $false
				Reason  = "No RRSIG records found for $Zone DNSKEY RRset"
				Dnskeys = $Private:DnskeyRecords
			}
		}

		$Private:ValidSigs = 0
		foreach ($Private:Rrsig in $Private:RrsigRecords) {
			$Private:RrsigData = $Private:Rrsig.RDataObject

			if (-not (Test-DnssecTimeWindow -Rrsig $Private:RrsigData)) { continue }

			$Private:SigningKey = Get-DnssecSigningKey -Rrsig $Private:RrsigData -DnskeyRrset $Private:DnskeyRecords
			if (-not $Private:SigningKey) { continue }

			$Private:SignedData = Get-DnssecSignedData -Rrsig $Private:RrsigData -Rrset $Private:DnskeyRecords
			if (Test-DnssecSignature -SignedData $Private:SignedData -Rrsig $Private:RrsigData -Dnskey $Private:SigningKey.RDataObject) {
				$Private:ValidSigs++
			}
		}

		if ($Private:ValidSigs -eq 0) {
			return [PSCustomObject]@{
				Valid   = $false
				Reason  = "No valid RRSIG signatures found for $Zone DNSKEY RRset"
				Dnskeys = $Private:DnskeyRecords
			}
		}

		return [PSCustomObject]@{
			Valid   = $true
			Reason  = "Zone $Zone validated ($Private:ValidSigs valid signature(s))"
			Dnskeys = $Private:DnskeyRecords
		}
	}
	catch {
		Write-MyCatchAudit -Source "Resolve-DnssecZone: unexpected error validating zone $Zone" -ErrorRecord $_
		return [PSCustomObject]@{
			Valid   = $false
			Reason  = "Unexpected error validating $Zone : $($_.Exception.Message)"
			Dnskeys = @()
		}
	}
}
