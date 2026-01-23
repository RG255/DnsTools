function Get-DnssecCanonicalRrWire 
{
	param(
		[Parameter(Mandatory)]$rr
	)

	$w = [DnsBinaryWriter]::new()
	$w.WriteBytes([byte[]](Get-DnssecCanonicalNameWire -name $rr.Name))
	$w.WriteUInt16BE([uint16]$rr.Type)
	$w.WriteUInt16BE([uint16]$rr.Class)
	$w.WriteUInt32BE([uint32]$rr.TTL)

	$rdata = $rr.RawRData
	$w.WriteUInt16BE([uint16]$rdata.Length)
	$w.WriteBytes($rdata)

	return $w.ToArray()
}