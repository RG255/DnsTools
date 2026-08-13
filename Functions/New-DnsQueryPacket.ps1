function New-DnsQueryPacket
{
	<#
	.SYNOPSIS
		Creates a DNS query packet in wire format.

	.DESCRIPTION
		Constructs a DNS query packet for the specified name and type, optionally with DNSSEC DO bit set.

	.PARAMETER name
		The domain name to query.

	.PARAMETER type
		The DNS record type to query (default: 1 = A record).

	.PARAMETER DoBit
		Set the DNSSEC OK (DO) bit in the EDNS OPT record.
	#>
	param(
		[string]$name,
		[int]$type = 1,
		[switch]$DoBit
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

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