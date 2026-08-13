function Get-RecordTypeAAAA
{
	<#
	.SYNOPSIS
		Parses DNS AAAA record RDATA.

	.DESCRIPTION
		Internal helper function to parse AAAA record RDATA from wire format bytes.

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

    return [DnsAaaaRecord]::Parse($rdata)
}
