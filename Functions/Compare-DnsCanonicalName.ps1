function Compare-DnsCanonicalName
{
	<#
		.SYNOPSIS
		Compares two domain names in DNSSEC canonical order (RFC 4034 section 6.1).

		.DESCRIPTION
		Added in 0.8 for NSEC denial-of-existence checks. Names are compared label by label starting from the rightmost
		(most significant) label; each label is compared as lower-cased bytes, and a name that is a proper prefix
		(in labels, read from the right) of another sorts first.

		.PARAMETER A
		First name ('' or '.' is the root).

		.PARAMETER B
		Second name.

		.OUTPUTS
		[int] negative when A sorts before B, 0 when equal, positive when A sorts after B.
	#>
	[CmdletBinding()]
	[OutputType([int])]
	param(
		[Parameter(Mandatory)]
		[AllowEmptyString()]
		[string]$A,

		[Parameter(Mandatory)]
		[AllowEmptyString()]
		[string]$B
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$labelsA = @($A.Trim().TrimEnd('.').ToLower().Split('.') | Where-Object -FilterScript { $_ -ne '' })
	$labelsB = @($B.Trim().TrimEnd('.').ToLower().Split('.') | Where-Object -FilterScript { $_ -ne '' })
	[array]::Reverse($labelsA)
	[array]::Reverse($labelsB)

	$shared = [Math]::Min($labelsA.Count, $labelsB.Count)
	for ($i = 0; $i -lt $shared; $i++)
	{
		$bytesA = [System.Text.Encoding]::ASCII.GetBytes($labelsA[$i])
		$bytesB = [System.Text.Encoding]::ASCII.GetBytes($labelsB[$i])
		$common = [Math]::Min($bytesA.Length, $bytesB.Length)
		for ($j = 0; $j -lt $common; $j++)
		{
			if ($bytesA[$j] -ne $bytesB[$j])
			{return [int]$bytesA[$j] - [int]$bytesB[$j]}
		}
		if ($bytesA.Length -ne $bytesB.Length)
		{return $bytesA.Length - $bytesB.Length}
	}

	return $labelsA.Count - $labelsB.Count
}
