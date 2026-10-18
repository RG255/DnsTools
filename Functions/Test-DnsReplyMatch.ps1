function Test-DnsReplyMatch
{
	<#
		.SYNOPSIS
		Returns $true when a DNS reply (wire format) answers a given query: same ID, QR set, same question.

		.DESCRIPTION
		Added in 0.8. Used for every reply the UDP resolver accepts, over UDP and over the TCP retry alike. The reply must
		be at least as long as the header plus the question, carry the query's 16-bit ID, have the QR (response) bit set,
		and repeat the query's question section (name, type, class), compared case-insensitively.

		.PARAMETER Query
		The query packet bytes.

		.PARAMETER Reply
		The candidate reply bytes.

		.OUTPUTS
		[bool]
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)]
		[byte[]]$Query,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[byte[]]$Reply
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	# End of the question section in the query: header (12) + labels + root label + QTYPE + QCLASS.
	$qEnd = 12
	while ($qEnd -lt $Query.Length -and $Query[$qEnd] -ne 0)
	{$qEnd += 1 + $Query[$qEnd]}
	$qEnd += 5

	if ($Query.Length -lt $qEnd -or $Reply.Length -lt $qEnd)
	{return $false}
	if ($Reply[0] -ne $Query[0] -or $Reply[1] -ne $Query[1])
	{return $false}
	if (($Reply[2] -band 0x80) -eq 0)
	{return $false}

	for ($i = 12; $i -lt $qEnd; $i++)
	{
		$a = $Query[$i]
		$b = $Reply[$i]
		if ($a -ge 65 -and $a -le 90) { $a += 32 }
		if ($b -ge 65 -and $b -le 90) { $b += 32 }
		if ($a -ne $b)
		{return $false}
	}

	return $true
}
