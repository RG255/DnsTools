function Get-DnssecKeyDigest 
{
	param(
		[string]$OwnerName,
		[DnsDnskeyRecord]$Dnskey,
		[int]$DigestType
	)

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