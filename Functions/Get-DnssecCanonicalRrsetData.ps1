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

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

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

		# [PSCustomObject], NOT a hashtable. Sort-Object -Property does NOT resolve a hashtable
		# KEY as a property under Windows PowerShell 5.1: every comparand comes back $null, all
		# elements compare EQUAL, and PS5's unstable sort then returns them REVERSED.
		#
		# Measured 2026-08-13, same input, both hosts:
		#     input 4,5 -> PS5 gave 5,4   PS7 gave 4,5
		#     input 5,4 -> PS5 gave 4,5   PS7 gave 4,5
		# i.e. PS5 was REVERSING, not sorting. It only looked correct when the input happened to
		# arrive in reverse order - which is why one unit test passed and the fixture test failed.
		#
		# This is a DNSSEC CORRECTNESS bug, not cosmetics: RFC 4034 6.3 requires the RRset to be
		# in canonical RDATA order before the signed data is built, so on PS5 signatures were
		# being computed/verified over a wrongly ordered RRset.
		#
		# !! Verify any change here with at least THREE records in a scrambled order. With two
		# reversed records "sorted" and "reversed" produce the SAME answer, and a 2-element test
		# reports a false pass - that is exactly how this survived.
		# Canonical RDATA (uncompressed, lower-cased embedded names) for real records; plain RawRData for
		# anything else (test doubles). See DnsResourceRecord.GetCanonicalRData().
		# Assigned inside each branch, NOT as `$x = if (...) {...}`: an if-expression result is unrolled into
		# object[] and the byte[] is lost (AddRange(IEnumerable[byte]) then fails to convert).
		if ($rr -is [DnsResourceRecord])
		{[byte[]]$rdataWire = $rr.GetCanonicalRData()}
		else
		{[byte[]]$rdataWire = $rr.RawRData}
		$records += ,[PSCustomObject]@{
			RdataWire = $rdataWire
			RdataKey  = [System.BitConverter]::ToString($rdataWire)
		}
	}

	$sorted = $records | Sort-Object -Property RdataKey

	return $sorted
}
