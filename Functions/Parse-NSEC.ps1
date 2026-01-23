function Parse-NSEC 
{
	param(
		[byte[]]$rdata,
		$packet,
		[int]$offset
	)

	return [DnsNsecRecord]::Parse($rdata)
}