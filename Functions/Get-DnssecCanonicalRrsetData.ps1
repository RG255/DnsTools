function Get-DnssecCanonicalRrsetData
{
	<#
	.SYNOPSIS
		Sorts an RRset into DNSSEC canonical order.

	.DESCRIPTION
		Sorts resource records in an RRset by their RDATA in canonical order for DNSSEC signature verification.

	.PARAMETER Rrset
		The array of DNS resource records to sort.
	#>
	param(
		[DnsResourceRecord[]]$Rrset
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	if (-not $Rrset -or $Rrset.Count -eq 0) 
	{throw 'RRset is empty.'}

	$name  = $Rrset[0].Name
	$type  = [uint16]$Rrset[0].Type
	$class = [uint16]$Rrset[0].Class

	$records = @()
	foreach ($rr in $Rrset) 
	{
		if ($rr.Name -ne $name -or $rr.Type -ne $type -or $rr.Class -ne $class) 
		{throw 'Mixed RRset: all records must share name, type, class.'}

		$rdataWire = $rr.RawRData
		$records += ,@{
			RdataWire = $rdataWire
			RdataKey  = [System.BitConverter]::ToString($rdataWire)
		}
	}

	$sorted = $records | Sort-Object -Property RdataKey

	return $sorted
}