function Test-DnssecAlgorithmSupported
{
	<#
		.SYNOPSIS
		Returns $true when this module can verify signatures (or compute DS digests) for a DNSSEC algorithm / digest type.

		.DESCRIPTION
		Added in 0.8. RFC 4035 section 5.2 and RFC 6840 section 5.2: a validator that does not implement the algorithm
		(or the DS digest type) of a signed delegation must treat that zone as UNSIGNED, not as bogus. Callers use this
		to tell "cannot verify" apart from "verified and wrong".

		Signature algorithms: 5, 7 (RSA/SHA-1), 8 (RSA/SHA-256), 10 (RSA/SHA-512), 13 (ECDSA P-256), 14 (ECDSA P-384),
		15 (Ed25519). DS digest types: 1 (SHA-1), 2 (SHA-256), 4 (SHA-384).

		.PARAMETER Algorithm
		A DNSSEC signature algorithm number.

		.PARAMETER DigestType
		A DS digest type number.

		.OUTPUTS
		[bool]
	#>
	[CmdletBinding(DefaultParameterSetName = 'Algorithm')]
	[OutputType([bool])]
	param(
		[Parameter(Mandatory, ParameterSetName = 'Algorithm')]
		[int]$Algorithm,

		[Parameter(Mandatory, ParameterSetName = 'Digest')]
		[int]$DigestType
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	if ($PSCmdlet.ParameterSetName -eq 'Digest')
	{return ($DigestType -in 1, 2, 4)}

	return ($Algorithm -in 5, 7, 8, 10, 13, 14, 15)
}
