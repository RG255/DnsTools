function Parse-A 
{
	param(
		[byte[]]$rdata,
		$packet,
		[int]$offset
	)

	return [DnsARecord]::Parse($rdata)
}