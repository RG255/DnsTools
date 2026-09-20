function Resolve-Dnssec
{
	<#
	.SYNOPSIS
		Performs DNSSEC-validated DNS resolution for a domain name.

	.DESCRIPTION
		Resolves a DNS name with full DNSSEC validation, verifying the chain of trust from the root zone to the target record.

	.PARAMETER name
		The fully qualified domain name to resolve.

	.PARAMETER type
		The DNS record type to query (default: 1 = A record).

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

	# 2026-09-15: whole body wrapped in Try/Catch (see the closing Catch at the bottom of this function)
	# after a try/catch coverage audit found this function had NO error handling anywhere - every
	# expected failure already returns a Valid=$false object with a Reason, but an unexpected exception
	# from any called helper (ConvertTo-DnsTypeCode, ConvertTo-HexString, Get-DnssecKeyDigest,
	# Test-DnssecRrsig, ...) had nothing to catch it and would propagate as a raw uncaught exception,
	# breaking the same "never throw, always return structured data" convention this function otherwise
	# already follows for every controlled failure path.
	try {

		# Convert type name to code if needed
		$TypeCode = ConvertTo-DnsTypeCode -Type $type

		# --- 1. Resolve target RRset ---
		# -Raw added 2026-09-15 (real bug, found while adding this function's outer Try/Catch): without
		# it, Resolve-DnsIterative returns its FORMATTED result (Status='Success'/'BailOut'/...,
		# Message=...), but every check below expects the RAW internal shape (Status='Final'/'BailOut',
		# Response=..., Reason=...) - so $iter.Status was NEVER 'Final' even on a real success, and the
		# very next line's $iter.Reason access threw under StrictMode (the property doesn't exist on the
		# formatted object either - it's Message). This meant Resolve-Dnssec crashed on EVERY call,
		# success or failure, until the Try/Catch above started catching it as a generic "unexpected
		# error" - confirmed live 2026-09-15 resolving cloudflare.com. Same fix applied to
		# Test-DnssecValidation.ps1's identical pattern the same day.
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
		$dnskeys = @($resp.Additional | Where-Object -FilterScript {$_.Type -eq 48})

		if ($answers.Count -eq 0)
		{
			return [pscustomobject]@{
				Valid   = $false
				Reason  = 'No answers returned'
				Answer  = $null
				Rrsigs  = $rrsigs
				Dnskeys = $dnskeys
			}
		}

		if ($rrsigs.Count -eq 0)
		{
			return [pscustomobject]@{
				Valid   = $false
				Reason  = 'No RRSIGs returned'
				Answer  = $answers
				Rrsigs  = @()
				Dnskeys = $dnskeys
			}
		}

		# --- 2. Ensure we have DNSKEYs ---
		if ($dnskeys.Count -eq 0)
		{
			Write-Verbose -Message "No DNSKEYs in Additional section, querying DNSKEY for $name"

			$iterKeys = Resolve-DnsIterative -name $name -type 48 -RootServers $RootServers -Trace:$Trace -Raw
			if ($iterKeys.Status -ne 'Final')
			{
				return [pscustomobject]@{
					Valid   = $false
					Reason  = "DNSKEY lookup failed: $($iterKeys.Reason)"
					Answer  = $answers
					Rrsigs  = $rrsigs
					Dnskeys = @()
				}
			}

			$dnskeys = @($iterKeys.Response.Answers | Where-Object -FilterScript {$_.Type -eq 48})
			if ($dnskeys.Count -eq 0)
			{
				return [pscustomobject]@{
					Valid   = $false
					Reason  = 'DNSKEY query returned no DNSKEY records'
					Answer  = $answers
					Rrsigs  = $rrsigs
					Dnskeys = @()
				}
			}
		}

		# --- 3. Derive parent zone and fetch DS ---

		# Normalize FQDN (remove trailing dot)
		$fqdn = $name.TrimEnd('.')

		# Determine parent zone
		if ($fqdn -eq '')
		{
			# Root has no parent
			$parentName = $null
		}
		else
		{
			$labels = $fqdn.Split('.')

			if ($labels.Count -lt 2)
			{
				# TLD has no parent DS
				$parentName = $null
			}
			else
			{
				# Parent is everything *after* the first label
				# e.g. cloudflare.com → com
				#      www.cloudflare.com → cloudflare.com
				$parentName = ($labels[1..($labels.Count - 1)] -join '.')
			}
		}

		$dsRecords = @()

		if ($parentName)
		{
			Write-Verbose -Message "Querying DS for $fqdn at parent $parentName"

			$iterDs = Resolve-DnsIterative -name $fqdn -type 43 -RootServers $RootServers -Trace:$Trace -Raw

			if ($iterDs.Status -eq 'Final')
			{
				$dsRecords = @($iterDs.Response.Answers | Where-Object -FilterScript {$_.Type -eq 43})
			}
		}

		# --- 4. DS → DNSKEY validation ---
		$dsValidatedKeys = @()

		if ($dsRecords.Count -gt 0)
		{
			foreach ($ds in $dsRecords)
			{
				$dsRdata = $ds.RDataObject

				# Match DNSKEYs by key tag + algorithm
				$candidateKeys = $dnskeys | Where-Object -FilterScript {
					$_.RDataObject.KeyTag    -eq $dsRdata.KeyTag   -and
					$_.RDataObject.Algorithm -eq $dsRdata.Algorithm
				}

				foreach ($ck in $candidateKeys)
				{
					# DigestType 0 → insecure delegation
					if ($dsRdata.DigestType -eq 0)
					{
						Write-Verbose -Message "DS digest type 0 -> insecure delegation for $fqdn"
						continue
					}

					$digest = Get-DnssecKeyDigest -OwnerName $fqdn -Dnskey $ck.RDataObject -DigestType $dsRdata.DigestType

					if ($Trace)
					{
						$dsHex  = ConvertTo-HexString -bytes $dsRdata.Digest
						$ourHex = if ($digest)
						{ConvertTo-HexString -bytes $digest}
						else
						{'<null>'}

						Write-Verbose -Message "DS digest (type $($dsRdata.DigestType)) from parent: $dsHex"
						Write-Verbose -Message "Computed DNSKEY digest for keytag $($ck.RDataObject.KeyTag): $ourHex"
					}

					if ($digest -and
						(ConvertTo-HexString -bytes $digest) -ceq (ConvertTo-HexString -bytes $dsRdata.Digest))
					{$dsValidatedKeys += $ck}
				}
			}

			if ($Trace)
			{
				if ($dsValidatedKeys.Count -gt 0)
				{Write-Verbose -Message "DS validation succeeded for $fqdn using $($dsValidatedKeys.Count) DNSKEY(s)"}
				else
				{Write-Verbose -Message "DS records present for $fqdn but none matched any DNSKEY"}
			}
		}

		# --- Fail only if real DS exists but none matched ---
		if (
			$dsRecords.Count -gt 0 -and
			$dsValidatedKeys.Count -eq 0 -and
			($dsRecords | Where-Object -FilterScript {$_.RDataObject.DigestType -ne 0})
		)
		{
			return [pscustomobject]@{
				Valid   = $false
				Reason  = 'DS records exist but none matched any DNSKEY (secure delegation failure)'
				Answer  = $answers
				Rrsigs  = $rrsigs
				Dnskeys = $dnskeys
				Ds      = $dsRecords
			}
		}

		# --- 5. Prefer DS-validated keys for RRSIG checking ---
		# --- 5. Select keys for RRSIG validation ---
		if ($dsValidatedKeys.Count -gt 0)
		{
			# DS validated → trust KSK + all ZSKs
			$keysToUse = @(
				$dsValidatedKeys +
				($dnskeys | Where-Object -FilterScript {$_.RDataObject.Flags -eq 256})  # ZSKs
			)
		}
		else
		{
			# No DS validation → insecure delegation → use all keys
			$keysToUse = $dnskeys
		}

		foreach ($sig in $rrsigs)
		{
			$Rrsig = $sig.RDataObject

			$key = $keysToUse |
				Where-Object -FilterScript {
					$_.RDataObject.KeyTag    -eq $Rrsig.KeyTag   -and
					$_.RDataObject.Algorithm -eq $Rrsig.Algorithm
				} |
				Select-Object -First 1

			if (-not $key)
			{
				return [pscustomobject]@{
					Valid   = $false
					Reason  = 'No matching DNSKEY for RRSIG (after DS filtering)'
					Answer  = $answers
					Rrsigs  = $rrsigs
					Dnskeys = $dnskeys
				}
			}

			$ok = Test-DnssecRrsig -Rrsig $Rrsig -Rrset $answers -DnskeyRrset @($key)

			if (-not $ok)
			{
				return [pscustomobject]@{
					Valid   = $false
					Reason  = 'RRSIG validation failed'
					Answer  = $answers
					Rrsigs  = $rrsigs
					Dnskeys = $dnskeys
				}
			}
		}

		return [pscustomobject]@{
			Valid   = $true
			Reason  = 'DNSSEC validation succeeded'
			Answer  = $answers
			Rrsigs  = $rrsigs
			Dnskeys = $dnskeys
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
