function Resolve-Dnssec
{
	<#
		.SYNOPSIS
		Performs DNSSEC-validated DNS resolution for a domain name.

		.DESCRIPTION
		Resolves a DNS name and validates the answer: every RRset in the answer must carry a valid RRSIG made
		by a key whose DNSKEY RRset is authenticated up the DS chain to a configured trust anchor.

		0.8: rewritten on Test-DnssecResponseSignature / Get-DnssecTrustedKey. Before 0.8 this function took
		the DNSKEYs from the (unauthenticated) Additional section or a plain lookup, treated the queried
		HOST NAME as a zone for the DS lookup, trusted any key in the DNSKEY set, and - because
		Test-DnssecRrsig returns an object, which is always truthy - never actually rejected a bad signature.

		Valid is $true only when Status is 'Secure'. Anything that cannot be proven (an unsigned RRset, a
		chain link that could not be fetched) is reported as not valid with the reason, never as valid.

		.PARAMETER name
		The fully qualified domain name to resolve.

		.PARAMETER type
		The DNS record type to query (default: A).

		.PARAMETER RootServers
		Array of root server IP addresses to use for resolution (defaults to module-configured root servers).

		.PARAMETER Trace
		Enable verbose trace output for debugging DNS resolution.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$name,

		$type = 'A',

		[Parameter(DontShow)]
		[string[]]$RootServers = $script:RootServerAddresses,

		[switch]$Trace
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	# Whole body in Try/Catch (2026-09-15): every controlled failure returns a Valid=$false object with a
	# Reason, and an unexpected exception from a helper must follow the same "never throw" convention.
	try {

		$TypeCode = ConvertTo-DnsTypeCode -Type $type

		# --- 1. Resolve target RRset (-Raw: the validators need the raw shape, not the formatted one) ---
		$iter = Resolve-DnsIterative -name $name -type $TypeCode -RootServers $RootServers -Trace:$Trace -Raw
		if ($iter.Status -ne 'Final')
		{
			return [pscustomobject]@{
				Valid   = $false
				Reason  = "Iterative resolution failed: $($iter.Reason)"
				Answer  = $null
				Rrsigs  = @()
				Dnskeys = @()
			}
		}

		$resp    = $iter.Response
		$rrsigs  = @($resp.Answers | Where-Object -FilterScript {$_.Type -eq 46})
		$answers = @($resp.Answers | Where-Object -FilterScript {$_.Type -ne 46})

		if ($answers.Count -eq 0)
		{
			return [pscustomobject]@{
				Valid   = $false
				Reason  = 'No answers returned'
				Answer  = $null
				Rrsigs  = $rrsigs
				Dnskeys = @()
			}
		}

		# --- 2. Validate every answer RRset against authenticated keys ---
		# (0.8: an answer with no RRSIG at all is now judged here too - provably unsigned, stripped, or not proven -
		# instead of being rejected up front as 'No RRSIGs returned'.)
		$check = Test-DnssecResponseSignature -Answers @($resp.Answers) -RootServers $RootServers

		$valid = ($check.Status -eq 'Secure')
		$reason = if ($valid)
		{'DNSSEC validation succeeded'}
		else
		{'DNSSEC validation {0}: {1}' -f $check.Status.ToLower(), (($check.Details | Where-Object -FilterScript {$_ -notmatch ': VALID$'}) -join '; ')}

		return [pscustomobject]@{
			Valid   = $valid
			Reason  = $reason
			Answer  = $answers
			Rrsigs  = $rrsigs
			Dnskeys = @($check.DnskeyRecords)
			Chain   = $check.Chain
			Status  = $check.Status
			Details = $check.Details
		}

	}
	catch {
		Write-MyCatchAudit -Source 'Resolve-Dnssec: unexpected error during DNSSEC validation' -ErrorRecord $_
		return [pscustomobject]@{
			Valid   = $false
			Reason  = "Unexpected error during DNSSEC validation: $($_.Exception.Message)"
			Answer  = $null
			Rrsigs  = @()
			Dnskeys = @()
		}
	}
}
