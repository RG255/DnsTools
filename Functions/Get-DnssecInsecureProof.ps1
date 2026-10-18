function Get-DnssecInsecureProof
{
	<#
		.SYNOPSIS
		Walks the zone cuts above a name and reports whether the name sits in a provably unsigned zone, a fully
		signed chain, or something that could not be established.

		.DESCRIPTION
		Added in 0.8. When an answer has no RRSIG, that is only a legitimate "unsigned zone" if the chain of trust
		stops at a delegation whose DS is provably absent (see Test-DnssecDsAbsence). If every zone cut down to the
		name is authenticated, the missing signature is a stripped one.

		Status:
		  Insecure       a zone cut on the way has a PROVEN absent DS; Zone names it.
		  Secure         every zone cut down to the name is authenticated - the name's zone is signed.
		  Bogus          a link in the chain positively failed.
		  Indeterminate  the walk could not be completed or absence could not be proven.

		.PARAMETER Name
		The owner name of the unsigned RRset.

		.PARAMETER RootServers
		Root server addresses used for the lookups.

		.PARAMETER Cache
		Trust cache shared with Get-DnssecTrustedKey so each zone is authenticated once per validation.

		.OUTPUTS
		[PSCustomObject] with Status, Zone and Reason.
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	param(
		[Parameter(Mandatory)]
		[string]$Name,

		[string[]]$RootServers = $script:RootServerAddresses,

		[hashtable]$Cache = @{}
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try
	{
		$labels = $Name.Trim().TrimEnd('.').ToLower().Split('.')

		$rootTrust = Get-DnssecTrustedKey -Zone '.' -RootServers $RootServers -Cache $Cache
		if ($rootTrust.Status -ne 'Secure')
		{return [pscustomobject]@{ Status = $rootTrust.Status; Zone = '.'; Reason = $rootTrust.Reason }}

		for ($i = $labels.Count - 1; $i -ge 0; $i--)
		{
			$candidate = ($labels[$i..($labels.Count - 1)] -join '.')
			if (-not (Test-DnsZoneApex -Name $candidate -RootServers $RootServers))
			{continue}

			$trust = Get-DnssecTrustedKey -Zone $candidate -RootServers $RootServers -Cache $Cache
			if ($trust.Status -eq 'Secure')
			{continue}

			return [pscustomobject]@{ Status = $trust.Status; Zone = $candidate; Reason = $trust.Reason }
		}

		return [pscustomobject]@{ Status = 'Secure'; Zone = $Name; Reason = 'Every zone cut down to the name is authenticated' }
	}
	catch
	{
		Write-MyCatchAudit -Source "Get-DnssecInsecureProof: unexpected error for '$Name'" -ErrorRecord $_
		return [pscustomobject]@{ Status = 'Indeterminate'; Zone = $Name; Reason = "Unexpected error: $($_.Exception.Message)" }
	}
}
