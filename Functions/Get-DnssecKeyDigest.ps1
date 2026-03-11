function Get-DnssecKeyDigest
{
	<#
	.SYNOPSIS
		Computes the DS digest for a DNSKEY record.

	.DESCRIPTION
		Calculates the DS (Delegation Signer) digest for a DNSKEY using the specified hash algorithm.

	.PARAMETER OwnerName
		The owner name of the DNSKEY record.

	.PARAMETER Dnskey
		The DNSKEY record object.

	.PARAMETER DigestType
		The digest algorithm type (1=SHA-1, 2=SHA-256, 4=SHA-384).
	#>
	param(
		[string]$OwnerName,
		[DnsDnskeyRecord]$Dnskey,
		[int]$DigestType
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	# Canonical owner name
	$nameWire = [byte[]](Get-DnssecCanonicalNameWire -name $OwnerName)

	# Build DNSKEY RDATA in canonical form
	$rdata = New-Object -TypeName System.Collections.Generic.List[byte]

	$flagsBytes = [BitConverter]::GetBytes([uint16]$Dnskey.Flags)
	if ([BitConverter]::IsLittleEndian) 
	{[Array]::Reverse($flagsBytes)}
	$rdata.AddRange([byte[]]$flagsBytes)

	$rdata.Add([byte]$Dnskey.Protocol)
	$rdata.Add([byte]$Dnskey.Algorithm)

	# Public key - force to byte[]
	if (-not $Dnskey.PublicKey) 
	{throw "DNSKEY.PublicKey is null for $OwnerName (Flags=$($Dnskey.Flags), Alg=$($Dnskey.Algorithm))"}

	$rdata.AddRange([byte[]]$Dnskey.PublicKey)

	# Combine name + RDATA for digest input
	$full = New-Object -TypeName System.Collections.Generic.List[byte]
	$full.AddRange([byte[]]$nameWire)
	$full.AddRange([byte[]]$rdata.ToArray())

	$data = [byte[]]$full.ToArray()

	switch ($DigestType) {
		0 
		{
			# Digest type 0 means "no digest" → insecure delegation
			return $null
		}
		1 
		{return [System.Security.Cryptography.SHA1]::Create().ComputeHash($data)}
		2 
		{return [System.Security.Cryptography.SHA256]::Create().ComputeHash($data)}
		4 
		{return [System.Security.Cryptography.SHA384]::Create().ComputeHash($data)}
		default 
		{throw "Unsupported DS digest type: $DigestType"}
	}
}