function Import-DnssecTrustAnchors
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

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	if (-not (Test-Path $Path))
	{throw "Trust anchor file not found: $Path"}

	# Always initialize the table
	$trustAnchorsVar = Get-Variable -Name TrustAnchors -Scope Script -ErrorAction SilentlyContinue
	if (-not $trustAnchorsVar)
	{$script:TrustAnchors = @{}}

	$json = Get-Content -Raw -Path $Path | ConvertFrom-Json

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

		# Insert validated anchor
		$script:TrustAnchors[$Zone] = @{
			KeyTag     = [int]$anchor.KeyTag
			Algorithm  = [int]$anchor.Algorithm
			DigestType = [int]$anchor.DigestType
			DigestHex  = $anchor.DigestHex.ToLower()
		}
	}
}