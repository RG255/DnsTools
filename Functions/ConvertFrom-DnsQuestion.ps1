function ConvertFrom-DnsQuestion
{
	<#
	.SYNOPSIS
		Parses a DNS question section from wire format bytes.

	.DESCRIPTION
		Extracts and parses a DNS question from a packet at the specified offset.

	.PARAMETER packet
		The DNS packet bytes containing the question.

	.PARAMETER offset
		Reference to the current offset in the packet (updated after parsing).
	#>
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
