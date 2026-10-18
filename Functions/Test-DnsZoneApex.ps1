function Test-DnsZoneApex
{
	<#
		.SYNOPSIS
		Returns $true when a name is the apex of a zone (it owns an SOA record), $false for a host or other non-apex name.

		.DESCRIPTION
		Added in 0.8. Test-DnssecValidation used to treat every label-suffix of the queried name as a zone, so for
		www.example.com it asked for DS and DNSKEY at www.example.com and reported a signed domain as failed. An SOA
		query answers exactly this: a zone apex returns its own SOA in the answer section, a non-apex name returns
		NODATA (or the record it is an alias for) with the SOA of the enclosing zone in the authority section.

		.PARAMETER Name
		The name to test ('example.com' or 'example.com.').

		.PARAMETER RootServers
		Root server addresses used for the lookup.

		.OUTPUTS
		[bool]
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)]
		[string]$Name,

		[string[]]$RootServers = $script:RootServerAddresses
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$bare = $Name.Trim().TrimEnd('.').ToLower()
		if ($bare -eq '')
		{return $true}

		$soa = Resolve-DnsIterative -Name $bare -Type 6 -RootServers $RootServers -Raw
		if ($soa.Status -ne 'Final')
		{return $false}

		$apex = @($soa.Response.Answers | Where-Object -FilterScript { $_.Type -eq 6 -and $_.Name.TrimEnd('.').ToLower() -eq $bare })
		return ($apex.Count -gt 0)
	}
	catch
	{
		Write-MyCatchAudit -Source "Test-DnsZoneApex: lookup failed for '$Name' - treated as not an apex" -ErrorRecord $_
		return $false
	}
}
