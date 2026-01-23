function Parse-DNSKEY 
{
	param(
		[byte[]]$rdata,
		$packet,
		[int]$offset
	)

	return [DnsDnskeyRecord]::Parse($rdata)
}