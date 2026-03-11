function ConvertFrom-DnsHeader
{
	<#
	.SYNOPSIS
		Parses a DNS header from wire format bytes.

	.DESCRIPTION
		Extracts and parses the DNS header section from a DNS packet byte array.

	.PARAMETER packet
		The DNS packet bytes containing the header.
	#>
    param(
        [byte[]]$packet
    )

    $r = [DnsBinaryReader]::new($packet)
    return [DnsHeader]::Parse($r)
}
