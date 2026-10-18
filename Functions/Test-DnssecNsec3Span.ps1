function Test-DnssecNsec3Span
{
	<#
		.SYNOPSIS
		Returns $true when an NSEC3 record's hash span (owner hash, next hash) covers a hash.

		.DESCRIPTION
		Added in 0.8 (shared by Test-DnssecNegativeResponse and Test-DnssecWildcardProof). Strictly between the two hashes,
		compared as unsigned big-endian bytes; the last record of the chain wraps round to the first.

		.PARAMETER Record
		An NSEC3 resource record (DnsResourceRecord whose RDataObject is a DnsNsec3Record).

		.PARAMETER Hash
		The hash to test, as a byte array.

		.OUTPUTS
		[bool]
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)]
		$Record,

		[Parameter(Mandatory)]
		[byte[]]$Hash
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$a = [BitConverter]::ToString($Record.RDataObject.OwnerHash)
	$b = [BitConverter]::ToString($Record.RDataObject.NextHash)
	$h = [BitConverter]::ToString($Hash)

	if ([string]::CompareOrdinal($a, $b) -lt 0)
	{return ([string]::CompareOrdinal($a, $h) -lt 0 -and [string]::CompareOrdinal($h, $b) -lt 0)}

	return ([string]::CompareOrdinal($h, $a) -gt 0 -or [string]::CompareOrdinal($h, $b) -lt 0)
}
