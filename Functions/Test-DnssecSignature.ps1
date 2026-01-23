function Test-DnssecSignature 
{
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$Rrset,
		[DnsDnskeyRecord]$Dnskey
	)

	$SignedData = Get-DnssecSignedData -Rrsig $Rrsig -Rrset $Rrset

	switch ($Dnskey.Algorithm) {
		8 
		{
			$rsa = [System.Security.Cryptography.RSA]::Create()
			$rsa.ImportSubjectPublicKeyInfo($Dnskey.PublicKey, [ref]0)
			return $rsa.VerifyData(
				$SignedData,
				$Rrsig.Signature,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			)
		}
		13 
		{
			$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
			$ecdsa.ImportSubjectPublicKeyInfo($Dnskey.PublicKey, [ref]0)
			return $ecdsa.VerifyData(
				$SignedData,
				$Rrsig.Signature,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256
			)
		}
		default 
		{throw "Unsupported DNSSEC algorithm: $($Dnskey.Algorithm)"}
	}
}
