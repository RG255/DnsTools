function Parse-DnsQuestion 
{
	param(
		[byte[]]$packet,
		[ref]$offset
	)

	$r = [DnsBinaryReader]::new($packet)
	$r.Position = $offset.Value

	$q = [DnsQuestion]::Parse($r)
	$offset.Value = $r.Position

	return $q
}
