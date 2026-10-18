function Test-DnssecSignature
{
	<#
		.SYNOPSIS
		Verifies a DNSSEC signature using a DNSKEY.

		.DESCRIPTION
		Cryptographically verifies that an RRSIG signature is valid for the given RRset using the specified DNSKEY.

		Algorithms: 5 and 7 (RSA/SHA-1), 8 (RSA/SHA-256), 10 (RSA/SHA-512), 13 (ECDSA P-256/SHA-256) and 14 (ECDSA
		P-384/SHA-384). 0.8 added 5, 7, 10 and 14. Ed25519/Ed448 (15, 16) are not available in the .NET versions
		this module supports and still throw "Unsupported DNSSEC algorithm" (callers count that as a failed
		verification, never as success). A malformed key (bad lengths) throws as well.

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

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$algorithm = [int]$Dnskey.Algorithm

	if ($algorithm -in 5, 7, 8, 10)
	{
		# RSA. DNSKEY format (RFC 3110): [exponent length (1 byte, or 0 + 2 bytes)][exponent][modulus]
		$hashName = [System.Security.Cryptography.HashAlgorithmName]::SHA256
		if ($algorithm -in 5, 7)
		{$hashName = [System.Security.Cryptography.HashAlgorithmName]::SHA1}
		if ($algorithm -eq 10)
		{$hashName = [System.Security.Cryptography.HashAlgorithmName]::SHA512}

		$keyBytes = $Dnskey.PublicKey
		if ($null -eq $keyBytes -or $keyBytes.Length -lt 3)
		{throw "Invalid RSA key: too short ($(@($keyBytes).Length) bytes)"}

		$offset = 0
		$expLen = [int]$keyBytes[$offset]
		$offset++
		if ($expLen -eq 0)
		{
			$expLen = ([int]$keyBytes[$offset] * 256) + [int]$keyBytes[$offset + 1]
			$offset += 2
		}
		if ($expLen -lt 1 -or ($offset + $expLen) -ge $keyBytes.Length)
		{throw "Invalid RSA key: exponent length $expLen does not fit the $($keyBytes.Length)-byte key"}

		$exponent = $keyBytes[$offset..($offset + $expLen - 1)]
		$offset += $expLen
		$modulus = $keyBytes[$offset..($keyBytes.Length - 1)]

		$rsaParams = [System.Security.Cryptography.RSAParameters]::new()
		$rsaParams.Exponent = $exponent
		$rsaParams.Modulus = $modulus

		$rsa = [System.Security.Cryptography.RSA]::Create()
		try
		{
			$rsa.ImportParameters($rsaParams)
			return $rsa.VerifyData($SignedData, $Rrsig.Signature, $hashName, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
		}
		finally
		{$rsa.Dispose()}
	}

	if ($algorithm -in 13, 14)
	{
		# ECDSA. DNSKEY format: [X][Y], 32 bytes each for P-256 (13), 48 bytes each for P-384 (14).
		# The RRSIG signature is the raw r||s form, which is .NET's default (IEEE P1363) format.
		$coordLen = 32
		$curveName = 'nistP256'
		$hashName = [System.Security.Cryptography.HashAlgorithmName]::SHA256
		if ($algorithm -eq 14)
		{
			$coordLen = 48
			$curveName = 'nistP384'
			$hashName = [System.Security.Cryptography.HashAlgorithmName]::SHA384
		}

		$keyBytes = $Dnskey.PublicKey
		if ($keyBytes.Length -ne (2 * $coordLen))
		{throw "Invalid ECDSA $curveName key length: expected $(2 * $coordLen) bytes, got $($keyBytes.Length)"}

		$ecParams = [System.Security.Cryptography.ECParameters]::new()
		$ecParams.Curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($curveName)
		$ecPoint = [System.Security.Cryptography.ECPoint]::new()
		$ecPoint.X = $keyBytes[0..($coordLen - 1)]
		$ecPoint.Y = $keyBytes[$coordLen..(2 * $coordLen - 1)]
		$ecParams.Q = $ecPoint

		$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
		try
		{
			$ecdsa.ImportParameters($ecParams)
			return $ecdsa.VerifyData([byte[]]$SignedData, [byte[]]$Rrsig.Signature, $hashName)
		}
		finally
		{$ecdsa.Dispose()}
	}

	if ($algorithm -eq 15)
	{
		# Ed25519 (RFC 8080): 32-byte public key, 64-byte signature. No .NET primitive exists, so a managed verifier is used.
		return (Test-DnssecEd25519Signature -PublicKey ([byte[]]$Dnskey.PublicKey) -Signature ([byte[]]$Rrsig.Signature) -Message $SignedData)
	}

	throw "Unsupported DNSSEC algorithm: $algorithm"
}
