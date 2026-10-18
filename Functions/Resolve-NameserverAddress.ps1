function Resolve-NameserverAddress
{
	<#
	.SYNOPSIS
		Resolves the IP addresses of a nameserver.

	.DESCRIPTION
		Resolves a nameserver hostname to IP addresses using bootstrap servers, handling glue records and recursive resolution.

	.PARAMETER nsName
		The nameserver hostname to resolve.

	.PARAMETER BootstrapServers
		Array of bootstrap server IP addresses to use for initial queries.

	.PARAMETER UseGlueOnly
		Return glue addresses immediately without authoritative resolution (for testing).

	.PARAMETER Trace
		Enable verbose trace output for debugging nameserver resolution.
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '',
		Justification = 'False positive - the analyzer cannot track the [string[]]-typed $glueAddrs variable through the loop/if nesting back to its "return $glueAddrs" statement; the declared OutputType is correct (confirmed by the explicit [string[]] type on the assignment).')]
	[CmdletBinding()]
	[OutputType([String[]])]
	param(
		[Parameter(Mandatory)]
		[string]$nsName,

		[Parameter(Mandatory)]
		[string[]]$BootstrapServers,

		[switch]$UseGlueOnly,
		[switch]$Trace,

		# Internal, set on the recursive call. The visited set is SHARED down the whole recursion (it used to be
		# created fresh in every call, so two zones whose nameservers sit in each other's zones with no glue
		# recursed without limit), and Depth caps what the set cannot catch.
		[Parameter(DontShow)]
		[AllowNull()]
		[System.Collections.Generic.HashSet[string]]$VisitedNames = $null,

		[Parameter(DontShow)]
		[int]$Depth = 0
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	if ($Depth -gt 6)
	{
		Write-Verbose -Message "Resolve-NameserverAddress: recursion depth limit reached resolving $nsName"
		return $null
	}

	$target = $nsName.TrimEnd('.').ToLower()
	$currentServers = $BootstrapServers | Sort-Object -Unique

	$visitedServerSets = New-Object System.Collections.Generic.HashSet[string]
	$visitedNsNames    = $VisitedNames
	if ($null -eq $visitedNsNames)
	{$visitedNsNames = New-Object System.Collections.Generic.HashSet[string]}
	$null = $visitedNsNames.Add($target)

	$maxIterations = 40
	$iteration = 0

	while ($iteration++ -lt $maxIterations)
	{
		$setKey = ($currentServers -join ',')
		if ($visitedServerSets.Contains($setKey)) {
			return $null
		}
		$null = $visitedServerSets.Add($setKey)

		foreach ($server in $currentServers)
		{
			try
			{
				$answers = New-Object System.Collections.Generic.List[string]

				foreach ($qType in 1, 28)
				{
					Write-Verbose -Message "Querying $server for $target (type $qType)"

					$query = New-DnsQueryPacket -name $target -type $qType -DoBit
					$bytes = Invoke-DnsUdpQuery -server $server -query $query
					$resp  = ConvertFrom-DnsPacket -packet $bytes

					Write-Verbose -Message "Received response: Q=$($resp.Questions[0].Name) AUTH=$($resp.Authority.Count)"

					# 0.8: accept an address only for the name asked about or a name reached from it through CNAMEs in
					# this same answer; an A/AAAA for any other owner is ignored (it was accepted for any owner).
					$allowedOwners = New-Object System.Collections.Generic.HashSet[string]
					$null = $allowedOwners.Add($target)
					foreach ($pass in 1..4)
					{
						foreach ($cn in @($resp.Answers | Where-Object { $_.Type -eq 5 -and $_.RDataObject }))
						{
							if ($allowedOwners.Contains($cn.Name.TrimEnd('.').ToLower()))
							{$null = $allowedOwners.Add($cn.RDataObject.Target.TrimEnd('.').ToLower())}
						}
					}

					foreach ($rr in $resp.Answers)
					{
						if ($rr.Type -in 1,28 -and $rr.RDataObject -and $rr.RDataObject.Address -and $allowedOwners.Contains($rr.Name.TrimEnd('.').ToLower())) {
							$null = $answers.Add($rr.RDataObject.Address)
						}
					}
				}

				if ($answers.Count -gt 0) {
					return ($answers | Sort-Object -Unique)
				}

				# -------------------------
				# Glue handling
				# -------------------------
				# 0.8: glue only for a nameserver the referral names (see Resolve-DnsIterative).
				$referredNs = @($resp.Authority | Where-Object { $_.Type -eq 2 -and $_.RDataObject } | ForEach-Object { $_.RDataObject.NsName.TrimEnd('.').ToLower() })
				[string[]]$glueAddrs = @($resp.Additional |
						Where-Object { $_.Type -in 1,28 -and $referredNs -contains $_.Name.TrimEnd('.').ToLower() } |
						ForEach-Object {
							if ($_.RDataObject -and $_.RDataObject.Address) {
								$_.RDataObject.Address
							}
						} |
						Where-Object { $_ } |
						Sort-Object -Unique)

				if ($glueAddrs.Count -gt 0) {

					if ($UseGlueOnly) {
						Write-Verbose -Message "Returning glue addresses: $($glueAddrs -join ', ')"
						return $glueAddrs
					}

					Write-Verbose -Message "Using glue as next-hop: $($glueAddrs -join ', ')"
					$currentServers = $glueAddrs
					break
				}

				# -------------------------
				# NS referrals
				# -------------------------
				$nsRecords = $resp.Authority | Where-Object { $_.Type -eq 2 }
				if ($nsRecords.Count -eq 0) { continue }

				$nsNames = $nsRecords |
					ForEach-Object {
						if ($_.RDataObject -and $_.RDataObject.NsName) {
							$_.RDataObject.NsName
						}
					} |
					Where-Object { $_ } |
					Sort-Object -Unique

				if ($nsNames.Count -eq 0) { continue }

				$resolvedNsAddrs = New-Object System.Collections.Generic.List[string]

				foreach ($ns in $nsNames)
				{
					$nsKey = $ns.TrimEnd('.').ToLower()
					if ($visitedNsNames.Contains($nsKey)) { continue }
					$null = $visitedNsNames.Add($nsKey)

					Write-Verbose -Message "Recursing to resolve NS name $nsKey"

					$nsAddrs = Resolve-NameserverAddress -nsName $ns -BootstrapServers $BootstrapServers -UseGlueOnly:$UseGlueOnly -Trace:$Trace -VisitedNames $visitedNsNames -Depth ($Depth + 1)
					if ($nsAddrs) {
						foreach ($a in $nsAddrs) {
							if (-not [string]::IsNullOrWhiteSpace($a)) {
								$null = $resolvedNsAddrs.Add($a)
							}
						}
					}
				}

				if ($resolvedNsAddrs.Count -gt 0) {
					return ($resolvedNsAddrs | Sort-Object -Unique)
				}
			}
			catch {
				# Trying the next server is correct; a single unreachable nameserver must not end the
				# lookup. But an entirely empty catch also hides genuine faults, and this function
				# returns $null on total failure - so the caller sees "could not resolve" with no way
				# to tell an unreachable server from a bug. Verbose leaves a trail, flow unchanged.
				Write-Verbose -Message ('Resolve-NameserverAddress: server query failed, trying next: {0}' -f $_.Exception.Message)
				Write-MyCatchAudit -Source 'Resolve-NameserverAddress: one candidate nameserver failed to query - trying the next is correct, but the function returns $null on total failure with no way to tell an unreachable server from a bug' -ErrorRecord $_
			}
		}
	}

	return $null
}
