function Test-DnssecSignature
{
	<#
	.SYNOPSIS
		Verifies a DNSSEC signature using a DNSKEY.

	.DESCRIPTION
		Cryptographically verifies that an RRSIG signature is valid for the given RRset using the specified DNSKEY.

	.PARAMETER SignedData
		The signed data (already computed from the RRset).

	.PARAMETER Rrsig
		The RRSIG record containing the signature.

	.PARAMETER Dnskey
		The DNSKEY to use for verification.
	#>
	param(
		[byte[]]$SignedData,
		[DnsRrsigRecord]$Rrsig,
		[DnsDnskeyRecord]$Dnskey
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	switch ($Dnskey.Algorithm) {
		8
		{
			# RSA/SHA-256 - Algorithm 8
			# DNSKEY format: [exponent_length][exponent][modulus]
			$keyBytes = $Dnskey.PublicKey
			$offset = 0

			# Read exponent length
			$expLen = $keyBytes[$offset]
			$offset++

			if ($expLen -eq 0) {
				# Extended length format (3 bytes total)
				$expLen = ($keyBytes[$offset] * 256) + $keyBytes[$offset + 1]
				$offset += 2
			}

			# Extract exponent and modulus
			$exponent = $keyBytes[$offset..($offset + $expLen - 1)]
			$offset += $expLen
			$modulus = $keyBytes[$offset..($keyBytes.Length - 1)]

			# Create RSA parameters
			$rsaParams = [System.Security.Cryptography.RSAParameters]::new()
			$rsaParams.Exponent = $exponent
			$rsaParams.Modulus = $modulus

			$rsa = [System.Security.Cryptography.RSA]::Create()
			$rsa.ImportParameters($rsaParams)

			return $rsa.VerifyData(
				$SignedData,
				$Rrsig.Signature,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			)
		}
		13
		{
			# ECDSAP256SHA256 - Algorithm 13
			# DNSKEY format: [X coordinate (32 bytes)][Y coordinate (32 bytes)]
			$keyBytes = $Dnskey.PublicKey

			if ($keyBytes.Length -ne 64) {
				throw "Invalid ECDSA P-256 key length: expected 64 bytes, got $($keyBytes.Length)"
			}

			$x = $keyBytes[0..31]
			$y = $keyBytes[32..63]

			# Create ECParameters for P-256 curve
			$ecParams = [System.Security.Cryptography.ECParameters]::new()
			$ecParams.Curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')

			# Create ECPoint structure
			$ecPoint = [System.Security.Cryptography.ECPoint]::new()
			$ecPoint.X = $x
			$ecPoint.Y = $y
			$ecParams.Q = $ecPoint

			$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
			$ecdsa.ImportParameters($ecParams)

			return $ecdsa.VerifyData(
				[byte[]]$SignedData,
				[byte[]]$Rrsig.Signature,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256
			)
		}
		default
		{throw "Unsupported DNSSEC algorithm: $($Dnskey.Algorithm)"}
	}
}
