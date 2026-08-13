function Get-DnssecKeyDigestHex
{
	<#
	.SYNOPSIS
		Computes the DS digest as a hexadecimal string.

	.DESCRIPTION
		Calculates the DS digest for a DNSKEY and returns it as a lowercase hexadecimal string.

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

	# Compute raw digest bytes
	$digest = [byte[]](Get-DnssecKeyDigest `
		-OwnerName $OwnerName `
		-Dnskey $Dnskey `
	-DigestType $DigestType)

	# Convert to lowercase hex without widening
	$sb = New-Object -TypeName System.Text.StringBuilder
	foreach ($b in $digest) 
	{[void]$sb.AppendFormat('{0:x2}', $b)}

	return $sb.ToString()
}
