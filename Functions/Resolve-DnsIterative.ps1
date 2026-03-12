function Resolve-DnsIterative
{
    <#
    .SYNOPSIS
        Performs iterative DNS resolution starting from root servers.

    .DESCRIPTION
        Resolves a DNS name by iteratively querying from root servers through authoritative nameservers to find the answer.
        Use -Name for forward DNS lookups and -IPAddr for reverse (PTR) lookups.

    .PARAMETER Name
        The fully qualified domain name to resolve. Use this for forward DNS lookups.

    .PARAMETER Address
        The IP address (IPv4 or IPv6) for reverse DNS (PTR) lookup.
        Automatically converts to the appropriate in-addr.arpa or ip6.arpa name.

    .PARAMETER Type
        The DNS record type to query. Not valid with -IPAddr (PTR is automatic).

    .PARAMETER Trace
        Enable verbose trace output for debugging DNS resolution.

    .PARAMETER ValidateDnssec
        Validate DNSSEC signatures on the response if RRSIG records are present.
        Adds DnssecStatus and DnssecDetails properties to the output.

    .PARAMETER DualStack
        Query for both A and AAAA records and merge the results.
        The -Type parameter is ignored when this switch is used.

    .PARAMETER DoT
        DNS-over-TLS server address. Queries use TLS instead of iterative UDP resolution.
        The DoT server performs recursive resolution on your behalf.
        Format: hostname or IP, with optional :port (default port: 853)
        Examples: "1.1.1.1", "dns.google:853", "cloudflare-dns.com"

    .PARAMETER DoH
        DNS-over-HTTPS endpoint URL. Queries use HTTPS instead of iterative UDP resolution.
        The DoH server performs recursive resolution on your behalf.
        Must be an HTTPS URL.
        Examples: "https://dns.google/dns-query", "https://1.1.1.1/dns-query"

    .EXAMPLE
        Resolve-DnsIterative -Name cloudflare.com -Type A
        Resolves the A records for cloudflare.com

    .EXAMPLE
        Resolve-DnsIterative -Name cloudflare.com -DualStack
        Resolves both A and AAAA records for cloudflare.com

    .EXAMPLE
        Resolve-DnsIterative -IPAddr 1.1.1.1
        Performs a reverse DNS lookup for 1.1.1.1

    .EXAMPLE
        Resolve-DnsIterative -IPAddr 2606:4700:4700::1111
        Performs a reverse DNS lookup for the IPv6 address

    .EXAMPLE
        Resolve-DnsIterative -Name cloudflare.com -Type A -DoT "1.1.1.1"
        Resolves A records using DNS-over-TLS via Cloudflare

    .EXAMPLE
        Resolve-DnsIterative -Name cloudflare.com -Type A -DoH "https://dns.google/dns-query"
        Resolves A records using DNS-over-HTTPS via Google

    .EXAMPLE
        Resolve-DnsIterative -Name example.com -DualStack -DoT "dns.quad9.net:853"
        Resolves both A and AAAA records using DNS-over-TLS via Quad9
    #>
    [CmdletBinding(DefaultParameterSetName = 'NameSet')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'NameSet', Position = 0)]
        [Parameter(Mandatory, ParameterSetName = 'DualStackSet', Position = 0)]
        [ValidateScript({
            # Validate DNS name syntax: labels separated by dots, each label 1-63 chars
            if ($_ -match '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.?$') {
                $true
            } else {
                throw "Invalid DNS name syntax: $_"
            }
        })]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'AddressSet', Position = 0)]
        [ValidateScript({
            # Validate IP address syntax (IPv4 or IPv6)
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($_, [ref]$ip)) {
                $true
            } else {
                throw "Invalid IP address syntax: $_"
            }
        })]
        [string]$IPAddr,

        [Parameter(ParameterSetName = 'NameSet')]
        [ValidateSet(
            # Most common types first (no PTR - use -IPAddr for that)
            'A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'SRV', 'CAA',
            # DNSSEC types
            'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'CDS', 'CDNSKEY',
            # Security/service types
            'TLSA', 'SSHFP', 'SMIMEA', 'SVCB', 'HTTPS',
            # Less common types
            'NAPTR', 'DNAME', 'LOC', 'HINFO', 'RP', 'AFSDB', 'WKS', 'SPF', 'URI',
            # Transfer/special types
            'TKEY', 'TSIG', 'IXFR', 'AXFR', 'ANY',
            # Numeric codes (same order, no 12 for PTR)
            1, 28, 15, 16, 5, 2, 6, 33, 257,
            43, 48, 46, 47, 50, 51, 59, 60,
            52, 44, 53, 64, 65,
            35, 39, 29, 13, 17, 18, 11, 99, 256,
            249, 250, 251, 252, 255)]
        $Type,

        [string[]]$RootServers = $script:RootServerAddresses,

        [switch]$Trace,

        [Parameter(DontShow)]
        [switch]$UseGlueOnly,

        [Parameter(DontShow)]
        [switch]$Raw,

        [switch]$ValidateDnssec,

        [Parameter(Mandatory, ParameterSetName = 'DualStackSet')]
        [switch]$DualStack,

        [Parameter()]
        [ValidateScript({
            # DoT: hostname/IP with optional :port (e.g., "1.1.1.1", "dns.google:853", "[2606:4700::1]:853")
            if ($_ -match '^(\[[0-9a-fA-F:]+\](:\d+)?|[a-zA-Z0-9.\-]+(:\d+)?)$') { $true }
            else { throw "Invalid DoT server format: $_. Expected hostname/IP with optional :port" }
        })]
        [string]$DoT,

        [Parameter()]
        [ValidateScript({
            # DoH: must be https:// URL
            if ($_ -match '^https://[a-zA-Z0-9.\-]+(:\d+)?(/[^\s]*)?$') { $true }
            else { throw "Invalid DoH endpoint: $_. Must be an HTTPS URL" }
        })]
        [string]$DoH
    )

    If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

    # Validate transport parameter exclusivity
    if ($DoT -and $DoH) {
        throw "The -DoT and -DoH parameters are mutually exclusive. Specify only one."
    }

    # Handle Address parameter - convert to reverse DNS name for PTR lookup
    $isPtrLookup = $false
    if ($PSCmdlet.ParameterSetName -eq 'AddressSet') {
        $Name = ConvertTo-ReverseDnsName -IPAddress $IPAddr
        $isPtrLookup = $true
        Write-Trace -Message "PTR query: converted $IPAddr to $Name"
    }

    # Handle DualStack mode - query both A and AAAA and merge results
    if ($DualStack) {
        $commonParams = @{
            Name = $Name
            RootServers = $RootServers
            Trace = $Trace
            UseGlueOnly = $UseGlueOnly
            Raw = $Raw
            ValidateDnssec = $ValidateDnssec
        }

        # Pass transport parameters if specified
        if ($DoT) { $commonParams['DoT'] = $DoT }
        if ($DoH) { $commonParams['DoH'] = $DoH }

        $resultA = Resolve-DnsIterative @commonParams -Type 'A'
        $resultAAAA = Resolve-DnsIterative @commonParams -Type 'AAAA'

        # For Raw mode, return both results in a combined object
        if ($Raw) {
            return [PSCustomObject]@{
                A = $resultA
                AAAA = $resultAAAA
            }
        }

        # For formatted mode, merge if both succeeded and metadata matches
        # First check if both have Success status (BailOut results don't have Server/Flags/RCode)
        $bothSuccess = ($resultA.Status -eq 'Success' -and $resultAAAA.Status -eq 'Success')

        $canMerge = $bothSuccess -and (
            $resultA.Server -eq $resultAAAA.Server -and
            $resultA.Flags -eq $resultAAAA.Flags -and
            $resultA.RCode -eq $resultAAAA.RCode
        )

        if ($canMerge) {
            # Merge the answers from both queries
            $mergedAnswers = @()
            if ($resultA.Answers) { $mergedAnswers += $resultA.Answers }
            if ($resultAAAA.Answers) { $mergedAnswers += $resultAAAA.Answers }

            # Use A result as base and update with merged data
            $merged = [PSCustomObject]@{
                QueryName       = $resultA.QueryName
                QueryType       = 'A+AAAA'
                Status          = $resultA.Status
                Server          = $resultA.Server
                Flags           = $resultA.Flags
                OpCode          = $resultA.OpCode
                RCode           = $resultA.RCode
                AnswerCount     = $mergedAnswers.Count
                Answers         = $mergedAnswers
                AuthorityCount  = $resultA.AuthorityCount
                Authority       = $resultA.Authority
                AdditionalCount = $resultA.AdditionalCount
                Additional      = $resultA.Additional
            }

            # Copy DNSSEC info if present (use A result's DNSSEC status)
            if ($resultA.PSObject.Properties['DnssecStatus']) {
                $merged | Add-Member -NotePropertyName 'DnssecStatus' -NotePropertyValue $resultA.DnssecStatus -Force
            }
            if ($resultA.PSObject.Properties['DnssecDetails']) {
                $merged | Add-Member -NotePropertyName 'DnssecDetails' -NotePropertyValue $resultA.DnssecDetails -Force
            }
            if ($resultA.PSObject.Properties['DnskeyRecords']) {
                $merged | Add-Member -NotePropertyName 'DnskeyRecords' -NotePropertyValue $resultA.DnskeyRecords -Force
            }
            if ($resultA.PSObject.Properties['DsRecords']) {
                $merged | Add-Member -NotePropertyName 'DsRecords' -NotePropertyValue $resultA.DsRecords -Force
            }

            return $merged
        }
        else {
            # Cannot merge - determine the appropriate status and message
            $statusMessage = if ($resultA.Status -ne 'Success' -and $resultAAAA.Status -ne 'Success') {
                'Both A and AAAA queries failed'
            } elseif ($resultA.Status -ne 'Success') {
                "A query failed: $($resultA.Message)"
            } elseif ($resultAAAA.Status -ne 'Success') {
                "AAAA query failed: $($resultAAAA.Message)"
            } else {
                'Results could not be merged due to differing server metadata'
            }

            return [PSCustomObject]@{
                QueryName = $Name
                QueryType = 'A+AAAA'
                Status    = 'Partial'
                Message   = $statusMessage
                A         = $resultA
                AAAA      = $resultAAAA
            }
        }
    }

    # Handle PTR lookup from -IPAddr parameter
    if ($isPtrLookup) {
        $TypeCode = 12  # PTR
        $TypeDisplay = 'PTR(12)'
    }
    else {
        # Require type parameter when not in DualStack mode
        if (-not $Type) {
            throw "The -Type parameter is required unless -DualStack is specified."
        }

        # Convert type name to code if needed
        $TypeCode = ConvertTo-DnsTypeCode -Type $Type
        $TypeDisplay = Format-DnsTypeName -Type $TypeCode
    }

    # Helper to return result with optional formatting
    function ReturnResult {
        param($RawResult)

        If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

        # Perform DNSSEC validation if requested and we have a response
        $dnssecResult = $null
        if ($ValidateDnssec -and $RawResult.Status -eq 'Final' -and $RawResult.Response) {
            $dnssecResult = ValidateDnssecResponse -Response $RawResult.Response -QueryName $fqdn -RootServers $RootServers
        }

        if ($Raw) {
            if ($dnssecResult) {
                $RawResult | Add-Member -NotePropertyName 'DnssecValidation' -NotePropertyValue $dnssecResult -Force
            }
            return $RawResult
        }
        $formatted = Format-DnsIterativeResult -Result $RawResult -QueryName $Name -QueryType $TypeDisplay
        if ($dnssecResult) {
            $formatted | Add-Member -NotePropertyName 'DnssecStatus' -NotePropertyValue $dnssecResult.Status -Force
            $formatted | Add-Member -NotePropertyName 'DnssecDetails' -NotePropertyValue $dnssecResult.Details -Force
            if ($dnssecResult.DnskeyRecords) {
                $formatted | Add-Member -NotePropertyName 'DnskeyRecords' -NotePropertyValue $dnssecResult.DnskeyRecords -Force
            }
            if ($dnssecResult.DsRecords) {
                $formatted | Add-Member -NotePropertyName 'DsRecords' -NotePropertyValue $dnssecResult.DsRecords -Force
            }
        }
        return $formatted
    }

    # Helper function to validate DNSSEC signatures on response
    function ValidateDnssecResponse {
        param(
            $Response,
            [string]$QueryName,
            [string[]]$RootServers
        )

        If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

        $details = @()
        $overallValid = $true

        # Check if response contains RRSIG records
        $rrsigRecords = @($Response.Answers | Where-Object { $_.Type -eq 46 })
        if ($rrsigRecords.Count -eq 0) {
            return @{
                Status = 'Unsigned'
                Details = @('No RRSIG records in response - response is not signed')
            }
        }

        $details += "Found $($rrsigRecords.Count) RRSIG record(s) in answer"

        # Get the zone name from the first RRSIG signer
        $signerName = $rrsigRecords[0].RDataObject.SignerName
        $details += "Signer zone: $signerName"

        try {
            # Query for DNSKEY records of the signer zone via iterative resolution
            $dnskeyResult = Resolve-DnsIterative -Name $signerName -Type 48 -RootServers $RootServers -Raw

            if ($dnskeyResult.Status -ne 'Final') {
                return @{
                    Status = 'Indeterminate'
                    Details = @("Could not retrieve DNSKEY for $signerName : $($dnskeyResult.Reason)")
                }
            }

            $dnskeyRecords = @($dnskeyResult.Response.Answers | Where-Object { $_.Type -eq 48 })
            if ($dnskeyRecords.Count -eq 0) {
                return @{
                    Status = 'Indeterminate'
                    Details = @("No DNSKEY records found for $signerName")
                }
            }

            $details += "Retrieved $($dnskeyRecords.Count) DNSKEY record(s) from $signerName"

            # Format DNSKEY records for output
            $formattedDnskeys = @()
            foreach ($dnskey in $dnskeyRecords) {
                $formattedDnskeys += Format-DnsRecord -Record $dnskey -Section 'Answer'
            }

            # Query for DS records from parent zone
            $formattedDs = @()
            try {
                $dsResult = Resolve-DnsIterative -name $signerName -type 43 -RootServers $RootServers -Raw
                if ($dsResult.Status -eq 'Final') {
                    $dsRecords = @($dsResult.Response.Answers | Where-Object { $_.Type -eq 43 })
                    if ($dsRecords.Count -gt 0) {
                        $details += "Retrieved $($dsRecords.Count) DS record(s) from parent zone"
                        foreach ($ds in $dsRecords) {
                            $formattedDs += Format-DnsRecord -Record $ds -Section 'Answer'
                        }
                    }
                }
            }
            catch {
                $details += "Could not retrieve DS records: $($_.Exception.Message)"
            }

            # Validate each RRSIG
            foreach ($rrsig in $rrsigRecords) {
                $rrsigData = $rrsig.RDataObject
                $typeCoveredName = Format-DnsTypeName -Type $rrsigData.TypeCovered

                # Get the RRset that this RRSIG covers
                $coveredRrset = @($Response.Answers | Where-Object {
                    $_.Type -eq $rrsigData.TypeCovered -and
                    $_.Name.TrimEnd('.').ToLower() -eq $rrsig.Name.TrimEnd('.').ToLower()
                })

                if ($coveredRrset.Count -eq 0) {
                    $details += "RRSIG KeyTag $($rrsigData.KeyTag) covers $typeCoveredName but no matching records found"
                    continue
                }

                # Validate the RRSIG
                $validationResult = Test-DnssecRrsig -Rrsig $rrsigData -Rrset $coveredRrset -DnskeyRrset $dnskeyRecords

                if ($validationResult.Valid) {
                    $details += "RRSIG KeyTag $($rrsigData.KeyTag) covering $typeCoveredName : VALID"
                } else {
                    $details += "RRSIG KeyTag $($rrsigData.KeyTag) covering $typeCoveredName : INVALID - $($validationResult.Reason)"
                    $overallValid = $false
                }
            }

            return @{
                Status = if ($overallValid) { 'Secure' } else { 'Bogus' }
                Details = $details
                DnskeyRecords = $formattedDnskeys
                DsRecords = $formattedDs
            }
        }
        catch {
            return @{
                Status = 'Indeterminate'
                Details = @("DNSSEC validation error: $($_.Exception.Message)")
            }
        }
    }

    $fqdn = $Name.TrimEnd('.').ToLower()

    # If DoT or DoH specified, perform direct recursive query (not iterative)
    if ($DoT -or $DoH) {
        Write-Trace -Message "Using encrypted transport - delegating iteration to resolver"

        $queryBytes = New-DnsQueryPacket -name $fqdn -type $TypeCode -DoBit
        $queryPacket = ConvertFrom-DnsWireBytes -bytes $queryBytes

        try {
            if ($DoH) {
                $client = [DnsDohClient]::new($DoH)
                $resp = $client.Query($queryPacket)
                $serverInfo = $DoH
            } else {
                # Parse DoT server:port
                $dotHost = $DoT
                $dotPort = 853
                if ($DoT -match '^\[([^\]]+)\]:(\d+)$') {
                    $dotHost = $Matches[1]
                    $dotPort = [int]$Matches[2]
                } elseif ($DoT -match '^([^:]+):(\d+)$' -and $DoT -notmatch ':.*:') {
                    $dotHost = $Matches[1]
                    $dotPort = [int]$Matches[2]
                }
                $client = [DnsDotClient]::new($dotHost, $dotPort)
                $resp = $client.Query($queryPacket)
                $serverInfo = "${dotHost}:${dotPort}"
            }

            $rawResult = [pscustomobject]@{
                Status   = 'Final'
                Response = $resp
                Reason   = "Answer from $serverInfo"
            }
            return (ReturnResult -RawResult $rawResult)
        }
        catch {
            $rawResult = [pscustomobject]@{
                Status = 'BailOut'
                Reason = "Transport error: $($_.Exception.Message)"
            }
            return (ReturnResult -RawResult $rawResult)
        }
    }

    # Randomize server order for load distribution, then deduplicate
    $currentServers = $RootServers | Sort-Object { Get-Random } | Select-Object -Unique
    $visitedServerSets = New-Object System.Collections.Generic.HashSet[string]

    $maxIterations = 40
    $iteration = 0

    while ($iteration++ -lt $maxIterations)
    {
        $setKey = ($currentServers -join ',')
        if ($visitedServerSets.Contains($setKey)) {
            $rawResult = [pscustomobject]@{
                Status = 'BailOut'
                Reason = "Server-set cycle detected: $setKey"
            }
            return (ReturnResult -RawResult $rawResult)
        }
        [void]$visitedServerSets.Add($setKey)

        foreach ($server in $currentServers)
        {
            try
            {
                Write-Trace -Message "Querying $server for $fqdn (type $TypeDisplay)"

                $query = New-DnsQueryPacket -name $fqdn -type $TypeCode -DoBit
                $bytes = Invoke-DnsUdpQuery -server $server -query $query
                $resp  = ConvertFrom-DnsPacket -packet $bytes

                if ($resp.Answers.Count -gt 0) {
                    # Check if we got a CNAME but wanted a different record type
                    $cnameRecords = @($resp.Answers | Where-Object { $_.Type -eq 5 })
                    $requestedTypeRecords = @($resp.Answers | Where-Object { $_.Type -eq $TypeCode })

                    # If we got what we asked for, or if we asked for CNAME, return immediately
                    if ($requestedTypeRecords.Count -gt 0 -or $TypeCode -eq 5) {
                        $rawResult = [pscustomobject]@{
                            Status   = 'Final'
                            Response = $resp
                            Reason   = "Answer found from $server"
                        }
                        return (ReturnResult -RawResult $rawResult)
                    }

                    # If we got a CNAME but wanted A/AAAA, follow the CNAME chain
                    if ($cnameRecords.Count -gt 0 -and $TypeCode -in @(1, 28)) {
                        $cnameTarget = $cnameRecords[0].RDataObject.Target
                        Write-Trace -Message "Following CNAME: $fqdn -> $cnameTarget"

                        # Recursively resolve the CNAME target
                        $cnameResult = Resolve-DnsIterative -name $cnameTarget -type $TypeCode -RootServers $RootServers -Raw

                        if ($cnameResult.Status -eq 'Final') {
                            # Combine the CNAME chain with the final answer
                            $combinedAnswers = @($resp.Answers) + @($cnameResult.Response.Answers)
                            $cnameResult.Response.Answers = $combinedAnswers
                            $cnameResult.Reason = "CNAME chain resolved via $server"
                        }

                        $rawResult = $cnameResult
                        return (ReturnResult -RawResult $rawResult)
                    }

                    # For other types, return what we got
                    $rawResult = [pscustomobject]@{
                        Status   = 'Final'
                        Response = $resp
                        Reason   = "Answer found from $server"
                    }
                    return (ReturnResult -RawResult $rawResult)
                }

                # Glue
                $glue = @($resp.Additional | Where-Object { $_.Type -in 1,28 })
                if ($glue.Count -gt 0) {
                    $glueAddrs = @($glue |
                        ForEach-Object {
                            if ($_.RDataObject -and $_.RDataObject.Address) {
                                $_.RDataObject.Address
                            }
                        } |
                        Where-Object { $_ } |
                        Sort-Object -Unique)

                    if ($glueAddrs.Count -gt 0) {
                        $currentServers = $glueAddrs
                        break
                    }
                }

                # NS referrals
                $nsRecords = $resp.Authority | Where-Object { $_.Type -eq 2 }
                if ($nsRecords.Count -gt 0) {

                    $nsNames = $nsRecords |
                        ForEach-Object {
                            if ($_.RDataObject -and $_.RDataObject.NsName) {
                                $_.RDataObject.NsName
                            }
                        } |
                        Where-Object { $_ } |
                        Sort-Object -Unique

                    if ($nsNames.Count -gt 0) {

                        $resolved = foreach ($nsName in $nsNames) {
                            Resolve-NameserverAddress `
                                -nsName $nsName `
                                -BootstrapServers $RootServers `
                                -UseGlueOnly:$UseGlueOnly `
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

    $rawResult = [pscustomobject]@{
        Status = 'BailOut'
        Reason = "Max iterations ($maxIterations) reached"
    }
    return (ReturnResult -RawResult $rawResult)
}