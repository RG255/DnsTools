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
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$nsName,

		[Parameter(Mandatory)]
		[string[]]$BootstrapServers,

		[switch]$UseGlueOnly,
		[switch]$Trace
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$target = $nsName.TrimEnd('.').ToLower()
	$currentServers = $BootstrapServers | Sort-Object -Unique

	$visitedServerSets = New-Object System.Collections.Generic.HashSet[string]
	$visitedNsNames    = New-Object System.Collections.Generic.HashSet[string]

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
					Write-Trace -Message "Querying $server for $target (type $qType)"

					$query = New-DnsQueryPacket -name $target -type $qType -DoBit
					$bytes = Invoke-DnsUdpQuery -server $server -query $query
					$resp  = ConvertFrom-DnsPacket -packet $bytes

					Write-Trace -Message "Received response: Q=$($resp.Questions[0].Name) AUTH=$($resp.Authority.Count)"

					foreach ($rr in $resp.Answers)
					{
						if ($rr.Type -in 1,28 -and $rr.RDataObject -and $rr.RDataObject.Address) {
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
				$glueAddrs = @($resp.Additional |
				Where-Object { $_.Type -in 1,28 } |
				ForEach-Object {
					if ($_.RDataObject -and $_.RDataObject.Address) {
						$_.RDataObject.Address
					}
				} |
				Where-Object { $_ } |
				Sort-Object -Unique)
				
				if ($glueAddrs.Count -gt 0) {

					if ($UseGlueOnly) {
						Write-Trace -Message "Returning glue addresses: $($glueAddrs -join ', ')"
						return $glueAddrs
					}

					Write-Trace -Message "Using glue as next-hop: $($glueAddrs -join ', ')"
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

					Write-Trace -Message "Recursing to resolve NS name $nsKey"

					$nsAddrs = Resolve-NameserverAddress -nsName $ns -BootstrapServers $BootstrapServers -UseGlueOnly:$UseGlueOnly -Trace:$Trace
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
				# ignore and try next server
			}
		}
	}

	return $null
}