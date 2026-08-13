function Get-DnssecSignedData
{
	<#
	.SYNOPSIS
		Constructs the signed data for DNSSEC signature verification.

	.DESCRIPTION
		Builds the canonical signed data by combining RRSIG metadata with the canonical RRset for cryptographic signature verification.

	.PARAMETER Rrsig
		The RRSIG record containing signature metadata.

	.PARAMETER Rrset
		The RRset being verified by the signature.
	#>
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$Rrset
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$bytes = New-Object -TypeName System.Collections.Generic.List[byte]

	# Type Covered
	$tc = [BitConverter]::GetBytes([uint16]$Rrsig.TypeCovered)
	if ([BitConverter]::IsLittleEndian) 
	{[Array]::Reverse($tc)}
	$bytes.AddRange($tc)

	# Algorithm, Labels
	$bytes.Add([byte]$Rrsig.Algorithm)
	$bytes.Add([byte]$Rrsig.Labels)

	# Original TTL
	$ttlBytes = [BitConverter]::GetBytes([uint32]$Rrsig.OriginalTTL)
	if ([BitConverter]::IsLittleEndian) 
	{[Array]::Reverse($ttlBytes)}
	$bytes.AddRange($ttlBytes)

	# Expiration, Inception
	foreach ($val in @($Rrsig.Expiration, $Rrsig.Inception)) 
	{
		$t = [BitConverter]::GetBytes([uint32]$val)
		if ([BitConverter]::IsLittleEndian) 
		{[Array]::Reverse($t)}
		$bytes.AddRange($t)
	}

	# Key Tag
	$kt = [BitConverter]::GetBytes([uint16]$Rrsig.KeyTag)
	if ([BitConverter]::IsLittleEndian) 
	{[Array]::Reverse($kt)}
	$bytes.AddRange($kt)

	# Signer Name (canonical)
	$bytes.AddRange( [byte[]](Get-DnssecCanonicalNameWire -name $Rrsig.SignerName) )

	# Canonical RRset
	$sorted = Get-DnssecCanonicalRrsetData -Rrset $Rrset

	$nameWire = [byte[]](Get-DnssecCanonicalNameWire -name $Rrset[0].Name)
	$type  = [uint16]$Rrset[0].Type
	$class = [uint16]$Rrset[0].Class

	$typeBytes  = [BitConverter]::GetBytes($type)
	$classBytes = [BitConverter]::GetBytes($class)
	if ([BitConverter]::IsLittleEndian) 
	{
		[Array]::Reverse($typeBytes)
		[Array]::Reverse($classBytes)
	}

	foreach ($rec in $sorted) 
	{
		$rdataWire = $rec.RdataWire

		# Owner name
		$bytes.AddRange($nameWire)

		# Type, Class
		$bytes.AddRange($typeBytes)
		$bytes.AddRange($classBytes)

		# TTL (Original TTL)
		$ttlBytes = [BitConverter]::GetBytes([uint32]$Rrsig.OriginalTTL)
		if ([BitConverter]::IsLittleEndian) 
		{[Array]::Reverse($ttlBytes)}
		$bytes.AddRange($ttlBytes)

		# RDLENGTH
		$rdlengthBytes = [BitConverter]::GetBytes([uint16]$rdataWire.Length)
		if ([BitConverter]::IsLittleEndian) 
		{[Array]::Reverse($rdlengthBytes)}
		$bytes.AddRange($rdlengthBytes)

		# RDATA
		$bytes.AddRange($rdataWire)
	}

	return $bytes.ToArray()
}