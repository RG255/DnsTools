function Test-DnssecNsec3OptOut 
{
	param(
		[DnsNsec3Record]$Nsec3,
		[bool]$IsDelegation
	)

	# Opt-Out flag is bit 0
	$optOut = ($Nsec3.Flags -band 0x01) -ne 0

	if (-not $optOut) 
	{return $false}

	# Opt-Out only allowed for unsigned delegations
	return $IsDelegation
}