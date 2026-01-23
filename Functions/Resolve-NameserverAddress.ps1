function Resolve-NameserverAddress 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$nsName,

		[Parameter(Mandatory)]
		[string[]]$BootstrapServers,

		[switch]$ReturnAuthoritative,
		[switch]$Trace
	)
	Write-host "### USING RESOLVER VERSION: $(Get-Date)" -ForegroundColor Yellow
	
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
					$resp  = Parse-DnsPacket -packet $bytes

					Write-Trace -Message "Received response: Q=$($resp.Questions[0].Name) AUTH=$($resp.Authority.Count)"
					Write-Host "### ADDITIONAL COUNT: $($resp.Additional.Count)" -ForegroundColor Cyan
					foreach ($rr in $resp.Additional) {
						Write-Host "### ADDITIONAL TYPE: $($rr.Type) NAME: $($rr.Name) RDATA: $($rr.RData)" -ForegroundColor DarkCyan
					}
					

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
				$glueAddrs = $resp.Additional |
				Where-Object { $_.Type -in 1,28 } |
				ForEach-Object {
					if ($_.RDataObject -and $_.RDataObject.Address) {
						$_.RDataObject.Address
					}
				} |
				Where-Object { $_ } |
				Sort-Object -Unique
				
				Write-Host "### GLUE COUNT: $($glueAddrs.Count)" -ForegroundColor Cyan
				
				if ($glueAddrs.Count -gt 0) {

					if (-not $ReturnAuthoritative) {
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

					$nsAddrs = Resolve-NameserverAddress -nsName $ns -BootstrapServers $BootstrapServers -ReturnAuthoritative:$ReturnAuthoritative -Trace:$Trace
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