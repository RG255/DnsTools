function Import-DnssecTrustAnchorFile
{
	<#
	.SYNOPSIS
		Imports DNSSEC trust anchors from a JSON file.

	.DESCRIPTION
		Loads DNSSEC trust anchors from a JSON file and adds them to the module's trust anchor store.

	.PARAMETER Path
		The path to the JSON file containing trust anchors.
	#>
	param(
		[string]$Path
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	if (-not (Test-Path $Path))
	{throw "Trust anchor file not found: $Path"}

	# Always initialize the table
	$trustAnchorsVar = Get-Variable -Name TrustAnchors -Scope Script -ErrorAction SilentlyContinue
	if (-not $trustAnchorsVar)
	{$script:TrustAnchors = @{}}

	$json = Get-Content -Raw -Path $Path | ConvertFrom-Json

	# Each zone holds a LIST of anchors (the root publishes several KSK digests, e.g. during a rollover).
	# A file import replaces what the store held for the zones it names, so reloading does not duplicate.
	$loaded = @{}

	foreach ($anchor in $json)
	{
		# Basic validation
		if (-not $anchor.Zone)
		{continue}
		if (-not $anchor.KeyTag)
		{continue}
		if (-not $anchor.Algorithm)
		{continue}
		if (-not $anchor.DigestType)
		{continue}
		if (-not $anchor.DigestHex)
		{continue}

		# Normalize zone name
		$Zone = $anchor.Zone.Trim().ToLower()
		if ($Zone -eq '')
		{$Zone = '.'}

		if (-not $loaded.ContainsKey($Zone))
		{$loaded[$Zone] = New-Object -TypeName System.Collections.Generic.List[object]}

		# Insert validated anchor
		$loaded[$Zone].Add(@{
				KeyTag     = [int]$anchor.KeyTag
				Algorithm  = [int]$anchor.Algorithm
				DigestType = [int]$anchor.DigestType
				DigestHex  = $anchor.DigestHex.ToLower()
			})
	}

	foreach ($zoneKey in @($loaded.Keys))
	{$script:TrustAnchors[$zoneKey] = $loaded[$zoneKey].ToArray()}
}
