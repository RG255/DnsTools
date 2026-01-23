function Import-DnssecTrustAnchors 
{
	param(
		[string]$Path
	)

	if (-not (Test-Path $Path)) 
	{throw "Trust anchor file not found: $Path"}

	# Always initialize the table
	if (-not $script:TrustAnchors) 
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