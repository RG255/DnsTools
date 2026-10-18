function Get-DnssecTrustedKey
{
	<#
		.SYNOPSIS
		Returns a zone's DNSKEY records only if they chain, signature by signature, to a configured trust anchor.

		.DESCRIPTION
		Added in 0.8. The chain walk every DNSSEC verdict in this module now rests on:

		Root: the root DNSKEY RRset must contain a key that matches a configured root trust anchor, and the
		RRset must be validly signed by such a key.

		Any other zone: the parent's keys must be trusted first (recursively); the zone's DS RRset must be
		validly signed by the parent's keys; the DNSKEY RRset must contain a key that the DS authenticates,
		and must be validly signed by such a DS-matched key.

		Status values:
		  Secure         the keys are authenticated; Dnskeys holds the zone's full DNSKEY RRset.
		  Bogus          a step positively failed (bad signature, DS mismatch, no anchor match).
		  Indeterminate  the chain could not be completed (no anchor configured, a lookup failed, or the DS
		                 could not be fetched). An authoritative "no DS" answer is currently reported by the
		                 iterative resolver as a failure, so an unsigned child also lands here rather than
		                 as a proven insecure delegation.

		A result is never Secure unless every link verified; there is no fall-back that trusts unauthenticated
		keys.

		.PARAMETER Zone
		The zone to authenticate ('.' for the root, 'example.com' or 'example.com.' otherwise).

		.PARAMETER RootServers
		Root server addresses used for the iterative lookups.

		.PARAMETER Cache
		Hashtable reused across calls so each zone is walked once per validation.

		.OUTPUTS
		[PSCustomObject] with Status, Reason, Dnskeys (DnsResourceRecord[]) and DsRecords (DnsResourceRecord[]).
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[AllowEmptyString()]
		[string]$Zone,

		[string[]]$RootServers = $script:RootServerAddresses,

		[hashtable]$Cache = @{}
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$bare = $Zone.Trim().TrimEnd('.').ToLower()
		$cacheKey = '.'
		if ($bare -ne '')
		{$cacheKey = $bare + '.'}

		if ($Cache.ContainsKey($cacheKey))
		{return $Cache[$cacheKey]}

		# Each zone is resolved by a flat helper that returns directly; the result is cached here once.
		$result = $null
		if ($bare -eq '')
		{$result = Get-DnssecRootTrust -RootServers $RootServers}
		if ($bare -ne '')
		{$result = Get-DnssecChildTrust -Bare $bare -CacheKey $cacheKey -RootServers $RootServers -Cache $Cache}

		$Cache[$cacheKey] = $result
		return $result
	}
	catch
	{
		Write-MyCatchAudit -Source "Get-DnssecTrustedKey: unexpected error authenticating zone '$Zone'" -ErrorRecord $_
		return New-DnssecTrustResult 'Indeterminate' "Unexpected error authenticating '$Zone': $($_.Exception.Message)" @() @()
	}
}

function Get-DnssecRootTrust
{
	# Root: anchor the DNSKEY RRset. Internal to Get-DnssecTrustedKey (flat early returns, no else chains).
	[CmdletBinding()]
	param(
		[string[]]$RootServers
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$anchors = @(Get-RootTrustAnchor)
		if ($anchors.Count -eq 0)
		{
			try
			{Initialize-DnssecTrustAnchorFile}
			catch
			{Write-MyCatchAudit -Source 'Get-DnssecRootTrust: loading the default trust anchor file failed - reported below as no anchor configured' -ErrorRecord $_}
			$anchors = @(Get-RootTrustAnchor)
		}
		if ($anchors.Count -eq 0)
		{return New-DnssecTrustResult 'Indeterminate' 'No root trust anchor is configured' @() @()}

		$resp = $null
		foreach ($server in @($RootServers | Sort-Object -Property { Get-Random } | Select-Object -First 6))
		{
			try
			{
				$bytes = Invoke-DnsUdpQuery -server $server -query (New-DnsQueryPacket -name '' -type 48 -DoBit)
				$candidate = ConvertFrom-DnsPacket -packet $bytes
				if (@($candidate.Answers | Where-Object -FilterScript { $_.Type -eq 48 }).Count -gt 0)
				{
					$resp = $candidate
					break
				}
			}
			catch
			{Write-MyCatchAudit -Source 'Get-DnssecRootTrust: one root server failed to return the root DNSKEY RRset - trying the next is correct' -ErrorRecord $_}
		}
		if ($null -eq $resp)
		{return New-DnssecTrustResult 'Indeterminate' 'Could not retrieve the root DNSKEY RRset from any root server' @() @()}

		$keys = @($resp.Answers | Where-Object -FilterScript { $_.Type -eq 48 })
		$sigs = @($resp.Answers | Where-Object -FilterScript { $_.Type -eq 46 })
		$anchored = @($keys | Where-Object -FilterScript { Test-DnssecAnchoredDnskey -Zone '.' -Dnskey $_.RDataObject })
		if ($anchored.Count -eq 0)
		{return New-DnssecTrustResult 'Bogus' 'No root DNSKEY matches a configured trust anchor' @() @()}

		$sigCheck = Test-DnssecRrsetSignature -Rrset $keys -Rrsigs $sigs -KeyRecords $anchored -ZoneName ''
		if (-not $sigCheck.Valid)
		{return New-DnssecTrustResult 'Bogus' "Root DNSKEY RRset is not validly signed by an anchored key: $($sigCheck.Reason)" @() @()}

		return New-DnssecTrustResult 'Secure' 'Root DNSKEY RRset anchored and signed' $keys @()
	}
	catch
	{
		Write-MyCatchAudit -Source 'Get-DnssecRootTrust: unexpected error anchoring the root' -ErrorRecord $_
		return New-DnssecTrustResult 'Indeterminate' "Unexpected error anchoring the root: $($_.Exception.Message)" @() @()
	}
}

function Get-DnssecChildTrust
{
	# Non-root: parent first, then DS (signed by the parent), then DNSKEY (signed by a DS-matched key).
	# Internal to Get-DnssecTrustedKey (flat early returns, no else chains).
	[CmdletBinding()]
	param(
		[string]$Bare,
		[string]$CacheKey,
		[string[]]$RootServers,
		[hashtable]$Cache
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$labels = $Bare.Split('.')
		$parent = '.'
		if ($labels.Count -gt 1)
		{$parent = ($labels[1..($labels.Count - 1)] -join '.') + '.'}

		$parentTrust = Get-DnssecTrustedKey -Zone $parent -RootServers $RootServers -Cache $Cache
		if ($parentTrust.Status -ne 'Secure')
		{return New-DnssecTrustResult $parentTrust.Status "Parent zone '$parent' is not authenticated: $($parentTrust.Reason)" @() @()}

		$dsResult = Resolve-DnsIterative -Name $Bare -Type 43 -RootServers $RootServers -Raw
		if ($dsResult.Status -ne 'Final')
		{return New-DnssecTrustResult 'Indeterminate' "DS lookup for '$CacheKey' did not return an answer (no DS published, or lookup failed): $($dsResult.Reason)" @() @()}

		$dsRecords = @($dsResult.Response.Answers | Where-Object -FilterScript { $_.Type -eq 43 -and $_.Name.TrimEnd('.').ToLower() -eq $Bare })
		$dsSigs = @($dsResult.Response.Answers | Where-Object -FilterScript { $_.Type -eq 46 })
		if ($dsRecords.Count -eq 0)
		{
			# No DS: an unsigned delegation - but only if the parent PROVES it. An unproven "no DS" could be a
			# stripped DS, so it is Indeterminate, never Insecure.
			$absence = Test-DnssecDsAbsence -Zone $Bare -ParentZone $parent -ParentKeys $parentTrust.Dnskeys -Response $dsResult.Response
			if ($absence.Proven)
			{return New-DnssecTrustResult 'Insecure' "'$CacheKey' is an insecure delegation: $($absence.Reason)" @() @()}
			return New-DnssecTrustResult 'Indeterminate' "No DS records published for '$CacheKey' and the absence is not proven: $($absence.Reason)" @() @()
		}

		$dsSigCheck = Test-DnssecRrsetSignature -Rrset $dsRecords -Rrsigs $dsSigs -KeyRecords $parentTrust.Dnskeys -ZoneName $parent
		if (-not $dsSigCheck.Valid)
		{return New-DnssecTrustResult 'Bogus' "DS RRset for '$CacheKey' is not validly signed by parent '$parent': $($dsSigCheck.Reason)" @() $dsRecords}

		$keyResult = Resolve-DnsIterative -Name $Bare -Type 48 -RootServers $RootServers -Raw
		if ($keyResult.Status -ne 'Final')
		{return New-DnssecTrustResult 'Indeterminate' "DNSKEY lookup for '$CacheKey' failed: $($keyResult.Reason)" @() $dsRecords}

		$keys = @($keyResult.Response.Answers | Where-Object -FilterScript { $_.Type -eq 48 -and $_.Name.TrimEnd('.').ToLower() -eq $Bare })
		$keySigs = @($keyResult.Response.Answers | Where-Object -FilterScript { $_.Type -eq 46 })
		$dsMatched = @(Get-DnssecDsMatchedKey -DsRecords $dsRecords -DnskeyRecords $keys -Zone $Bare)
		if ($dsMatched.Count -eq 0)
		{return New-DnssecTrustResult 'Bogus' "No DNSKEY in '$CacheKey' is authenticated by its DS records (secure delegation failure)" @() $dsRecords}

		$keySigCheck = Test-DnssecRrsetSignature -Rrset $keys -Rrsigs $keySigs -KeyRecords $dsMatched -ZoneName $Bare
		if (-not $keySigCheck.Valid)
		{return New-DnssecTrustResult 'Bogus' "DNSKEY RRset for '$CacheKey' is not validly signed by a DS-authenticated key: $($keySigCheck.Reason)" @() $dsRecords}

		return New-DnssecTrustResult 'Secure' "DNSKEY RRset for '$CacheKey' authenticated via DS" $keys $dsRecords
	}
	catch
	{
		Write-MyCatchAudit -Source "Get-DnssecChildTrust: unexpected error authenticating '$Bare'" -ErrorRecord $_
		return New-DnssecTrustResult 'Indeterminate' "Unexpected error authenticating '$Bare': $($_.Exception.Message)" @() @()
	}
}

function New-DnssecTrustResult
{
	# Internal: the result shape shared by Get-DnssecTrustedKey and its helpers.
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
		Justification = 'Builds and returns an in-memory object; New here means constructs a value, not a system-state change.')]
	[CmdletBinding()]
	param($Status, $Reason, $Keys, $Ds)

	[pscustomobject]@{
		Status    = $Status
		Reason    = $Reason
		Dnskeys   = @($Keys)
		DsRecords = @($Ds)
	}
}
