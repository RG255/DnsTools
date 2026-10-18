function Test-DnssecNsecSpan
{
	<#
		.SYNOPSIS
		Returns $true when an NSEC record's span (owner, next) covers a name, in DNSSEC canonical order.

		.DESCRIPTION
		Added in 0.8 (shared by Test-DnssecNegativeResponse and Test-DnssecWildcardProof). "Covers" means strictly between
		the owner and the next name; the last NSEC of a zone wraps round to the apex, and a single-record zone covers every
		name except its own.

		.PARAMETER Record
		An NSEC resource record (DnsResourceRecord whose RDataObject is a DnsNsecRecord).

		.PARAMETER Name
		The name to test.

		.OUTPUTS
		[bool]
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory)]
		$Record,

		[Parameter(Mandatory)]
		[AllowEmptyString()]
		[string]$Name
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$target = $Name.Trim().TrimEnd('.').ToLower()
	$owner = $Record.Name.TrimEnd('.').ToLower()
	$next = $Record.RDataObject.NextDomainName.TrimEnd('.').ToLower()

	if ((Compare-DnsCanonicalName -A $owner -B $next) -lt 0)
	{return ((Compare-DnsCanonicalName -A $owner -B $target) -lt 0 -and (Compare-DnsCanonicalName -A $target -B $next) -lt 0)}

	return ((Compare-DnsCanonicalName -A $target -B $owner) -gt 0 -or (Compare-DnsCanonicalName -A $target -B $next) -lt 0)
}
