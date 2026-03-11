function Test-DnssecRrsig
{
	<#
	.SYNOPSIS
		Validates an RRSIG signature against a DNSKEY RRset.

	.DESCRIPTION
		Verifies that an RRSIG signature is valid by checking the time window and cryptographic signature using the matching DNSKEY.

	.PARAMETER Rrsig
		The RRSIG record to validate.

	.PARAMETER Rrset
		The RRset that was signed.

	.PARAMETER DnskeyRrset
		The DNSKEY RRset to search for the signing key.
	#>
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$Rrset,
		[DnsResourceRecord[]]$DnskeyRrset
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	if (-not (Test-DnssecTimeWindow -Rrsig $Rrsig)) 
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = 'RRSIG not valid at current time'
		}
	}

	$dnskeyRR = Get-DnssecSigningKey -Rrsig $Rrsig -DnskeyRrset $DnskeyRrset
	if (-not $dnskeyRR)
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = "No matching DNSKEY for key tag $($Rrsig.KeyTag)"
		}
	}
	$Dnskey = [DnsDnskeyRecord]$dnskeyRR.RDataObject

	$SignedData = Get-DnssecSignedData -Rrsig $Rrsig -Rrset $Rrset

	$ok = Test-DnssecSignature -SignedData $SignedData -Rrsig $Rrsig -Dnskey $Dnskey

	return [pscustomobject]@{
		Valid  = $ok
		Reason = if ($ok) 
		{'OK'}
		else 
		{'Cryptographic signature check failed'}
	}
}