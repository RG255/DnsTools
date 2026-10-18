function Test-DnssecDsAbsence
{
	<#
		.SYNOPSIS
		Proves, from signed NSEC / NSEC3 records, that a delegation has no DS record (an insecure delegation).

		.DESCRIPTION
		Added in 0.8. An authoritative "no DS" answer (NODATA) is only trustworthy if the parent signs a proof of
		it; otherwise an attacker can strip a real DS and downgrade a signed zone to "unsigned". This checks the
		denial in the NODATA response against the PARENT zone's authenticated keys:

		NSEC   an NSEC record owned by the child name, whose type bitmap has NS and lacks DS and SOA, signed by the parent.
		NSEC3  an NSEC3 record whose hash is the child name's hash, bitmap has NS and lacks DS and SOA, signed by the
		       parent; or, when no record matches, an opt-out proof (RFC 5155 section 7.2.4): a closest-encloser
		       record and a covering record with the opt-out flag set, both signed by the parent.

		Anything else is "not proven" - the caller must not treat the zone as provably unsigned.

		.PARAMETER Zone
		The child zone name (no trailing dot required).

		.PARAMETER ParentZone
		The parent zone name (the signer of the denial).

		.PARAMETER ParentKeys
		The parent zone's authenticated DNSKEY records (DnsResourceRecord).

		.PARAMETER Response
		The DnsPacket of the DS NODATA answer.

		.OUTPUTS
		[PSCustomObject] with Proven ([bool]) and Reason ([string]).
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[string]$Zone,

		[Parameter(Mandatory)]
		[AllowEmptyString()]
		[string]$ParentZone,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[psobject[]]$ParentKeys,

		[Parameter(Mandatory)]
		$Response
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$bare = $Zone.Trim().TrimEnd('.').ToLower()
		$authority = @($Response.Authority)
		$sigs = @($authority | Where-Object -FilterScript { $_.Type -eq 46 })

		# ---- NSEC ----
		foreach ($rr in @($authority | Where-Object -FilterScript { $_.Type -eq 47 -and $_.Name.TrimEnd('.').ToLower() -eq $bare }))
		{
			$types = @($rr.RDataObject.Types)
			if ($types -contains 43 -or $types -contains 6 -or $types -notcontains 2)
			{continue}
			$sig = Test-DnssecRrsetSignature -Rrset @($rr) -Rrsigs $sigs -KeyRecords $ParentKeys -ZoneName $ParentZone
			if ($sig.Valid)
			{return [pscustomobject]@{ Proven = $true; Reason = "Signed NSEC at '$bare' has NS and no DS/SOA" }}
		}

		# ---- NSEC3 ----
		$nsec3 = @($authority | Where-Object -FilterScript { $_.Type -eq 50 -and $_.RDataObject -is [DnsNsec3Record] })
		if ($nsec3.Count -eq 0)
		{return [pscustomobject]@{ Proven = $false; Reason = 'No NSEC/NSEC3 record in the DS NODATA response' }}

		$params = $nsec3[0].RDataObject
		$alg = [int]$params.HashAlgorithm
		$iter = [int]$params.Iterations
		[byte[]]$salt = @($params.Salt)
		if ($alg -ne 1)
		{return [pscustomobject]@{ Proven = $false; Reason = "NSEC3 hash algorithm $alg is not supported" }}
		if ($iter -gt 2500)
		{return [pscustomobject]@{ Proven = $false; Reason = "NSEC3 iterations $iter exceed the 2500 limit (RFC 9276 guidance)" }}

		$hash = Get-DnssecNsec3Hash -name ($bare + '.') -Algorithm $alg -Iterations $iter -salt $salt
		$hashHex = [BitConverter]::ToString($hash)

		foreach ($rr in $nsec3)
		{
			if ([BitConverter]::ToString($rr.RDataObject.OwnerHash) -ne $hashHex)
			{continue}
			$types = @($rr.RDataObject.Types)
			if ($types -contains 43 -or $types -contains 6 -or $types -notcontains 2)
			{continue}
			$sig = Test-DnssecRrsetSignature -Rrset @($rr) -Rrsigs $sigs -KeyRecords $ParentKeys -ZoneName $ParentZone
			if ($sig.Valid)
			{return [pscustomobject]@{ Proven = $true; Reason = "Signed NSEC3 matching '$bare' has NS and no DS/SOA" }}
		}

		# Opt-out: closest encloser exists, and the next closer name is covered by an opt-out NSEC3.
		$records = @($nsec3 | ForEach-Object { $_.RDataObject })
		$ce = Find-DnssecNsec3ClosestEncloser -QueryName $bare -Nsec3Records $records -HashAlgorithm $alg -Iterations $iter -salt $salt
		if (-not $ce)
		{return [pscustomobject]@{ Proven = $false; Reason = 'No matching NSEC3 and no closest encloser in the response' }}

		$cover = Find-DnssecNsec3NextCloser -QueryName $bare -ClosestEncloserName $ce.Name -Nsec3Records $records -HashAlgorithm $alg -Iterations $iter -salt $salt
		if (-not $cover)
		{return [pscustomobject]@{ Proven = $false; Reason = 'No NSEC3 record covers the next closer name' }}
		if (($cover.Flags -band 1) -eq 0)
		{return [pscustomobject]@{ Proven = $false; Reason = 'The covering NSEC3 record is not an opt-out record' }}

		$ceRr = @($nsec3 | Where-Object -FilterScript { $_.RDataObject -eq $ce.Record })
		$coverRr = @($nsec3 | Where-Object -FilterScript { $_.RDataObject -eq $cover })
		if ($ceRr.Count -eq 0 -or $coverRr.Count -eq 0)
		{return [pscustomobject]@{ Proven = $false; Reason = 'Could not map the opt-out proof records back to the response' }}

		$ceSig = Test-DnssecRrsetSignature -Rrset @($ceRr[0]) -Rrsigs $sigs -KeyRecords $ParentKeys -ZoneName $ParentZone
		$coverSig = Test-DnssecRrsetSignature -Rrset @($coverRr[0]) -Rrsigs $sigs -KeyRecords $ParentKeys -ZoneName $ParentZone
		if (-not $ceSig.Valid -or -not $coverSig.Valid)
		{return [pscustomobject]@{ Proven = $false; Reason = 'An opt-out proof record is not validly signed by the parent' }}

		return [pscustomobject]@{ Proven = $true; Reason = "Signed NSEC3 opt-out proof covers '$bare'" }
	}
	catch
	{
		Write-MyCatchAudit -Source "Test-DnssecDsAbsence: unexpected error proving DS absence for '$Zone'" -ErrorRecord $_
		return [pscustomobject]@{ Proven = $false; Reason = "Unexpected error: $($_.Exception.Message)" }
	}
}
