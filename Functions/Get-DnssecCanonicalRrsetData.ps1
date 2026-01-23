function Get-DnssecCanonicalRrsetData 
{
	param(
		[DnsResourceRecord[]]$Rrset
	)

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