function Get-RecordTypeA
{
	<#
	.SYNOPSIS
		Parses DNS A record RDATA.

	.DESCRIPTION
		Internal helper function to parse A record RDATA from wire format bytes.

	.PARAMETER rdata
		The RDATA bytes to parse.

	.PARAMETER packet
		The full DNS packet (unused, for signature compatibility).

	.PARAMETER offset
		The offset in the packet (unused, for signature compatibility).
	#>
    param(
        [byte[]]$rdata,
        $packet,
        [int]$offset
    )

    return [DnsARecord]::Parse($rdata)
}
