function Resolve-DnsIterative 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$name,

        [Parameter(Mandatory)]
        [int]$type,

        [Parameter(Mandatory)]
        [string[]]$RootServers,

        [switch]$Trace,
        [switch]$UseAuthoritativeNsResolution
    )

    $fqdn = $name.TrimEnd('.').ToLower()
    $currentServers = $RootServers | Sort-Object -Unique
    $visitedServerSets = New-Object System.Collections.Generic.HashSet[string]

    $maxIterations = 40
    $iteration = 0

    while ($iteration++ -lt $maxIterations)
    {
        $setKey = ($currentServers -join ',')
        if ($visitedServerSets.Contains($setKey)) {
            return [pscustomobject]@{
                Status = 'BailOut'
                Reason = "Server-set cycle detected: $setKey"
            }
        }
        $visitedServerSets.Add($setKey)

        foreach ($server in $currentServers)
        {
            try
            {
                Write-Trace -Message "Querying $server for $fqdn (type $type)"

                $query = New-DnsQueryPacket -name $fqdn -type $type -DoBit
                $bytes = Invoke-DnsUdpQuery -server $server -query $query
                $resp  = Parse-DnsPacket -packet $bytes

                if ($resp.Answers.Count -gt 0) {
                    return [pscustomobject]@{
                        Status   = 'Final'
                        Response = $resp
                        Reason   = "Answer found from $server"
                    }
                }

                # Glue
                $glue = $resp.Additional | Where-Object { $_.Type -in 1,28 }
                if ($glue.Count -gt 0) {
                    $glueAddrs = $glue |
                        ForEach-Object { $_.RDataObject.Address } |
                        Where-Object { $_ } |
                        Sort-Object -Unique

                    if ($glueAddrs.Count -gt 0) {
                        $currentServers = $glueAddrs
                        break
                    }
                }

                # NS referrals
                $nsRecords = $resp.Authority | Where-Object { $_.Type -eq 2 }
                if ($nsRecords.Count -gt 0) {

                    $nsNames = $nsRecords |
                        ForEach-Object { $_.RDataObject.NsName } |
                        Where-Object { $_ } |
                        Sort-Object -Unique

                    if ($nsNames.Count -gt 0) {

                        $resolved = foreach ($nsName in $nsNames) {
                            Resolve-NameserverAddress `
                                -nsName $nsName `
                                -BootstrapServers $RootServers `
                                -ReturnAuthoritative:$UseAuthoritativeNsResolution `
                                -Trace:$Trace
                        }

                        $resolved = $resolved | Where-Object { $_ } | Sort-Object -Unique

                        if ($resolved.Count -gt 0) {
                            $currentServers = $resolved
                            break
                        }
                    }
                }
            }
            catch {
                # ignore and try next server
            }
        }
    }

    return [pscustomobject]@{
        Status = 'BailOut'
        Reason = "Max iterations ($maxIterations) reached"
    }
}