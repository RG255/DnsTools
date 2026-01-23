function Parse-DnsHeader 
{
	param(
		[byte[]]$packet
	)

	$r = [DnsBinaryReader]::new($packet)
	return [DnsHeader]::Parse($r)
}