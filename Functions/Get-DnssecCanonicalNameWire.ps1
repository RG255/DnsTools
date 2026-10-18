function Get-DnssecCanonicalNameWire
{
	<#
	.SYNOPSIS
		Converts a DNS name to DNSSEC canonical wire format.

	.DESCRIPTION
		Converts a domain name to its canonical wire format representation as specified in RFC 4034 for DNSSEC signature verification.

	.PARAMETER name
		The domain name to convert.
	#>
	param([string]$name)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$labels = $name.TrimEnd('.').ToLower().Split('.')

	# Force a strongly typed List[byte]
	$bytes = New-Object -TypeName 'System.Collections.Generic.List[byte]'

	foreach ($label in $labels)
	{
		# The root ('' or '.') splits to a single empty label; it is encoded by the terminating 0 alone.
		# Without this skip the root became 00 00, which broke every digest/signature over the root zone.
		if ($label.Length -eq 0)
		{continue}

		$labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)

		# Explicit cast ensures Add() receives a byte
		$bytes.Add([byte]$labelBytes.Length)

		# Explicit cast ensures AddRange() receives IEnumerable[byte]
		$bytes.AddRange([byte[]]$labelBytes)
	}

	# Root label
	$bytes.Add([byte]0)

	# Force return type to byte[]
	return [byte[]]$bytes.ToArray()
}
