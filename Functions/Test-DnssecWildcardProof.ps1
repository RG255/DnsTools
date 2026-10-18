function Test-DnssecWildcardProof
{
	<#
		.SYNOPSIS
		Checks the signed proof that a wildcard-expanded answer's exact name does not exist (RFC 4035 section 5.3.4).

		.DESCRIPTION
		Added in 0.8. An RRset whose RRSIG has fewer labels than its owner name was synthesised from a wildcard. The signature
		alone is replayable (the same wildcard RRSIG fits any name under it), so a validator must also see a signed NSEC or
		NSEC3 record, in the authority section, showing that no closer match exists:

		NSEC   one NSEC covers the owner name.
		NSEC3  one NSEC3 covers the hash of the next closer name (the owner trimmed to LabelCount + 1 labels).

		Either record must be validly signed by the zone.

		.PARAMETER Owner
		The expanded owner name of the answer RRset.

		.PARAMETER LabelCount
		The RRSIG Labels field (labels of the wildcard owner, not counting '*').

		.PARAMETER Authority
		The authority-section records of the response.

		.PARAMETER Keys
		The zone's authenticated DNSKEY records.

		.PARAMETER Zone
		The signing zone.

		.OUTPUTS
		[PSCustomObject] with Proven ([bool]) and Reason ([string]).
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[string]$Owner,

		[Parameter(Mandatory)]
		[int]$LabelCount,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[psobject[]]$Authority,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[psobject[]]$Keys,

		[Parameter(Mandatory)]
		[AllowEmptyString()]
		[string]$Zone
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$name = $Owner.Trim().TrimEnd('.').ToLower()
		$sigs = @($Authority | Where-Object -FilterScript { $_.Type -eq 46 })

		foreach ($rr in @($Authority | Where-Object -FilterScript { $_.Type -eq 47 -and $_.RDataObject -is [DnsNsecRecord] }))
		{
			if (-not (Test-DnssecNsecSpan -Record $rr -Name $name))
			{continue}
			if ((Test-DnssecRrsetSignature -Rrset @($rr) -Rrsigs $sigs -KeyRecords $Keys -ZoneName $Zone).Valid)
			{return [pscustomobject]@{ Proven = $true; Reason = "Signed NSEC covers '$name'" }}
		}

		$nsec3 = @($Authority | Where-Object -FilterScript { $_.Type -eq 50 -and $_.RDataObject -is [DnsNsec3Record] })
		if ($nsec3.Count -eq 0)
		{return [pscustomobject]@{ Proven = $false; Reason = 'No NSEC/NSEC3 record in the response' }}

		$params = $nsec3[0].RDataObject
		if ([int]$params.HashAlgorithm -ne 1 -or [int]$params.Iterations -gt 2500)
		{return [pscustomobject]@{ Proven = $false; Reason = 'NSEC3 parameters are not supported' }}
		[byte[]]$salt = @($params.Salt)

		$labels = @($name.Split('.'))
		if ($labels.Count -le $LabelCount)
		{return [pscustomobject]@{ Proven = $false; Reason = 'The owner has no more labels than the RRSIG Labels field' }}
		$nextCloser = ($labels[($labels.Count - $LabelCount - 1)..($labels.Count - 1)] -join '.')
		$hash = Get-DnssecNsec3Hash -name ($nextCloser + '.') -Algorithm 1 -Iterations ([int]$params.Iterations) -salt $salt

		foreach ($rr in $nsec3)
		{
			if (-not (Test-DnssecNsec3Span -Record $rr -Hash $hash))
			{continue}
			if ((Test-DnssecRrsetSignature -Rrset @($rr) -Rrsigs $sigs -KeyRecords $Keys -ZoneName $Zone).Valid)
			{return [pscustomobject]@{ Proven = $true; Reason = "Signed NSEC3 covers the next closer name '$nextCloser'" }}
		}

		return [pscustomobject]@{ Proven = $false; Reason = "No validly signed NSEC/NSEC3 covers '$name'" }
	}
	catch
	{
		Write-MyCatchAudit -Source "Test-DnssecWildcardProof: unexpected error for '$Owner'" -ErrorRecord $_
		return [pscustomobject]@{ Proven = $false; Reason = "Unexpected error: $($_.Exception.Message)" }
	}
}
