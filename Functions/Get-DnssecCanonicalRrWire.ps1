function Get-DnssecCanonicalRrWire
{
	<#
	.SYNOPSIS
		Converts a DNS resource record to DNSSEC canonical wire format.

	.DESCRIPTION
		Converts a resource record to its canonical wire format for DNSSEC signature verification as specified in RFC 4034.

	.PARAMETER rr
		The DNS resource record to convert.
	#>
	param(
		[Parameter(Mandatory)]$rr
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$w = [DnsBinaryWriter]::new()
	$w.WriteBytes([byte[]](Get-DnssecCanonicalNameWire -name $rr.Name))
	$w.WriteUInt16BE([uint16]$rr.Type)
	$w.WriteUInt16BE([uint16]$rr.Class)
	$w.WriteUInt32BE([uint32]$rr.TTL)

	if ($rr -is [DnsResourceRecord])
	{[byte[]]$rdata = $rr.GetCanonicalRData()}
	else
	{[byte[]]$rdata = $rr.RawRData}
	$w.WriteUInt16BE([uint16]$rdata.Length)
	$w.WriteBytes($rdata)

	return $w.ToArray()
}
