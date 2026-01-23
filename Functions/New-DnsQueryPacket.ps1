function New-DnsQueryPacket 
{
	param(
		[string]$name,
		[int]$type = 1,
		[switch]$DoBit
	)

	$pkt = [DnsPacket]::new()
	$pkt.Header = [DnsHeader]::new(
		(Get-Random -Minimum 0 -Maximum 65535),
		0x0100,
		1, 0, 0, 0
	)

	$pkt.Questions.Add(
		[DnsQuestion]::new($name, $type, 1)
	)

	if ($DoBit) 
	{
		$opt = [DnsOptRecord]::new(
			4096,
			0,
			0,
			0x8000,
			@()
		)
		$pkt.Opt = $opt
	}

	return $pkt.ToArray()
}