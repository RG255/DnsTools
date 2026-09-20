function Test-DnssecNsec3OptOut
{
	<#
	.SYNOPSIS
		Checks if NSEC3 Opt-Out is applicable.

	.DESCRIPTION
		Validates whether NSEC3 Opt-Out flag is correctly set for unsigned delegations.

	.PARAMETER Nsec3
		The NSEC3 record to check.

	.PARAMETER IsDelegation
		Whether the name is a delegation point.
	#>
	param(
		[DnsNsec3Record]$Nsec3,
		[bool]$IsDelegation
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	# Opt-Out flag is bit 0
	$optOut = ($Nsec3.Flags -band 0x01) -ne 0

	if (-not $optOut)
	{return $false}

	# Opt-Out only allowed for unsigned delegations
	return $IsDelegation
}
