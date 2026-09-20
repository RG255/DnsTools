function Resolve-DnsIterative
{
	<#
    .SYNOPSIS
        Performs iterative DNS resolution starting from root servers.

    .DESCRIPTION
        Resolves a DNS name by iteratively querying from root servers through authoritative nameservers to find the answer.
        Use -Name for forward DNS lookups and -IPAddr for reverse (PTR) lookups.

        Every outcome, including a caller usage mistake (e.g. omitting -Type), comes back as a
        returned object with a Status property - never a thrown exception - so programmatic callers
        can always branch on $result.Status without needing try/catch. Status values: Success (a real
        answer), BailOut (resolution could not complete - see Message/Reason), Indeterminate (DNSSEC
        validation could not complete), Partial (-DualStack: one of A/AAAA failed or the two could not
        be merged), InvalidArgument (a caller-usage mistake, such as omitting -Type or specifying both
        -DoT and -DoH).

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
		[string]$Name,

		[Parameter(Mandatory, ParameterSetName = 'AddressSet', Position = 0)]
		[string]$IPAddr,

		# No [ValidateSet(...)] and no inline [ArgumentCompleter(...)] here on purpose. ValidateSet was
		# tried first and removed - confirmed live 2026-09-15: when a parameter carries BOTH ValidateSet
		# and ArgumentCompleter, PowerShell's completion engine only invokes the ArgumentCompleter once
		# at least one character has been typed, silently falling back to ValidateSet's own raw
		# (mnemonic names and numeric codes mixed together) completion for a bare Tab press on an empty
		# word instead. The completer itself has since moved to Register-DnsTypeCompleter.ps1 (shared
		# with ConvertTo-DnsTypeCode, which has the identical "name or code" contract) via
		# Register-ArgumentCompleter, rather than staying duplicated here as an inline attribute.
		# Validation happens via ConvertTo-DnsTypeCode's own "Unknown DNS record type: $Type" check a
		# few lines down instead of at parameter-bind time - still fails fast, just very slightly later
		# in the function body, not before it starts.
		[Parameter(ParameterSetName = 'NameSet')]
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
		[string]$DoT,

		[Parameter()]
		[string]$DoH
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	# Parameter syntax validation, moved out of [ValidateScript(...)] attributes and into the function
	# body 2026-09-15 (see .DESCRIPTION) so a caller-usage mistake reports as Status='InvalidArgument'
	# instead of throwing a ParameterBindingException - matching the DoT/DoH-exclusivity and -Type
	# checks just below. Each Message states the SPECIFIC defect (which label, which length, which
	# character) rather than a bare "Invalid X" - Test-DnsNameSyntax's own Reason already does this for
	# -Name; the -IPAddr/-DoT/-DoH checks here are inline since each is a single TryParse/regex test,
	# not worth a dedicated helper function of their own.
	if ($PSCmdlet.ParameterSetName -eq 'NameSet' -or $PSCmdlet.ParameterSetName -eq 'DualStackSet') {
		$nameCheck = Test-DnsNameSyntax -Name $Name
		if (-not $nameCheck.IsValid) {
			return [PSCustomObject]@{
				QueryName = $Name
				QueryType = $null
				Status    = 'InvalidArgument'
				Message   = $nameCheck.Reason
			}
		}
	}

	if ($PSCmdlet.ParameterSetName -eq 'AddressSet') {
		$parsedIp = $null
		if (-not [System.Net.IPAddress]::TryParse($IPAddr, [ref]$parsedIp)) {
			return [PSCustomObject]@{
				QueryName = $IPAddr
				QueryType = $null
				Status    = 'InvalidArgument'
				Message   = "The -IPAddr value '$IPAddr' is not a valid IPv4 or IPv6 address."
			}
		}
	}

	if ($DoT -and $DoT -notmatch '^(\[[0-9a-fA-F:]+\](:\d+)?|[a-zA-Z0-9.\-]+(:\d+)?)$') {
		return [PSCustomObject]@{
			QueryName = $Name
			QueryType = $null
			Status    = 'InvalidArgument'
			Message   = "The -DoT value '$DoT' is not a valid hostname/IP with an optional :port (e.g. '1.1.1.1', 'dns.google:853', '[2606:4700::1]:853')."
		}
	}

	if ($DoH -and $DoH -notmatch '^https://[a-zA-Z0-9.\-]+(:\d+)?(/[^\s]*)?$') {
		return [PSCustomObject]@{
			QueryName = $Name
			QueryType = $null
			Status    = 'InvalidArgument'
			Message   = "The -DoH value '$DoH' is not a valid HTTPS URL (e.g. 'https://dns.google/dns-query')."
		}
	}

	# Validate transport parameter exclusivity
	# Returned as a Status object (not thrown) for the same reason as the -Type check below: this
	# function already reports every other outcome (Final/BailOut/Indeterminate/Partial/...) as data a
	# caller checks via $result.Status, not via try/catch - a caller-usage mistake like this is no
	# different in kind from "resolution failed", and forcing a try/catch onto only THIS one case
	# (found live 2026-09-15, reported by the user, for the -Type check) made it impossible to handle
	# programmatically the same simple way as everything else this function can return.
	if ($DoT -and $DoH) {
		return [PSCustomObject]@{
			QueryName = $Name
			QueryType = $null
			Status    = 'InvalidArgument'
			Message   = "The -DoT and -DoH parameters are mutually exclusive. Specify only one."
		}
	}

	# Handle Address parameter - convert to reverse DNS name for PTR lookup
	$isPtrLookup = $false
	if ($PSCmdlet.ParameterSetName -eq 'AddressSet') {
		# $IPAddr already passed the -IPAddr syntax check above, so a failure here is an internal bug in
		# ConvertTo-ReverseDnsName itself, not a caller mistake - reported as BailOut (not InvalidArgument)
		# and via Write-MyCatchAudit, same convention as every other unexpected-failure path in this
		# function, instead of letting it propagate as a raw uncaught exception (found live 2026-09-15
		# during the try/catch coverage audit - this call had no guard at all).
		try {
			$Name = ConvertTo-ReverseDnsName -IPAddress $IPAddr
		}
		catch {
			Write-MyCatchAudit -Source 'Resolve-DnsIterative: ConvertTo-ReverseDnsName failed for an already-validated -IPAddr value' -ErrorRecord $_
			return [PSCustomObject]@{
				QueryName = $IPAddr
				QueryType = $null
				Status    = 'BailOut'
				Message   = "Failed to convert '$IPAddr' to a reverse-DNS name: $($_.Exception.Message)"
			}
		}
		$isPtrLookup = $true
		Write-Verbose -Message "PTR query: converted $IPAddr to $Name"
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
		# Require type parameter when not in DualStack mode. Returned as a Status object, not thrown -
		# see the -DoT/-DoH check above for why: a caller checking $result.Status can handle this
		# exactly like every other outcome this function reports, with no try/catch required.
		if (-not $Type) {
			return [PSCustomObject]@{
				QueryName = $Name
				QueryType = $null
				Status    = 'InvalidArgument'
				Message   = "The -Type parameter is required unless -DualStack is specified. Example: -Type A (or AAAA, MX, TXT, NS, ...; press Tab after -Type to see the full list, or pass a numeric type code such as 15)."
			}
		}

		# Convert type name to code if needed
		$TypeCode = ConvertTo-DnsTypeCode -Type $Type
		$TypeDisplay = Format-DnsTypeName -Type $TypeCode
	}

	# Helper to return result with optional formatting
	function ReturnResult {
		param($RawResult)

		If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

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
			# Bracket notation, not dot notation: ValidateDnssecResponse's 'Unsigned'/'Indeterminate'
			# returns are @{ Status = ...; Details = ... } ONLY - no DnskeyRecords/DsRecords keys at
			# all (those only exist on the 'Secure'/'Bogus' path, once DNSKEY/DS retrieval actually
			# ran). Dot notation on a genuinely absent hashtable key throws "The property '...' cannot
			# be found on this object" under this module's own Set-StrictMode -Version Latest -
			# confirmed live 2026-09-15 resolving www.microsoft.com -ValidateDnssec (an unsigned name):
			# the thrown exception was swallowed by the OUTER per-server try/catch a few lines up
			# (logged as "server query failed, trying next"), discarding an already-successful CNAME
			# chain resolution and leaving the iterative loop to eventually hit its own
			# server-set-cycle bailout instead - a real answer silently replaced by a misleading one.
			# Same root cause and same fix as Get-MyError.ps1's identical bug the same day.
			$formatted | Add-Member -NotePropertyName 'DnssecStatus' -NotePropertyValue $dnssecResult['Status'] -Force
			$formatted | Add-Member -NotePropertyName 'DnssecDetails' -NotePropertyValue $dnssecResult['Details'] -Force
			if ($dnssecResult['DnskeyRecords']) {
				$formatted | Add-Member -NotePropertyName 'DnskeyRecords' -NotePropertyValue $dnssecResult['DnskeyRecords'] -Force
			}
			if ($dnssecResult['DsRecords']) {
				$formatted | Add-Member -NotePropertyName 'DsRecords' -NotePropertyValue $dnssecResult['DsRecords'] -Force
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

		If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

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
		Write-Verbose -Message "Using encrypted transport - delegating iteration to resolver"

		try {
			# New-DnsQueryPacket/ConvertFrom-DnsWireBuffer moved inside this try 2026-09-15 (found
			# unguarded during the try/catch coverage audit) - a malformed packet here is the same kind
			# of transport-path failure as the DoH/DoT query below, and the existing catch already
			# reports it as BailOut via the same Reason shape.
			$queryBytes = New-DnsQueryPacket -name $fqdn -type $TypeCode -DoBit
			$queryPacket = ConvertFrom-DnsWireBuffer -bytes $queryBytes

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

	# Captures the most recent per-server failure (e.g. a malformed-packet parse exception from
	# ConvertFrom-DnsPacket) so it can be surfaced in the eventual BailOut's Reason instead of only
	# reaching -Verbose/Write-MyCatchAudit - added 2026-09-15 after confirming the low-level DNS wire
	# parsers (DnsBinaryReader, DnsPacket, etc.) already throw specific, useful messages ("DNS name
	# compression loop detected at offset 42") that were being silently dropped by the catch below once
	# every server in the set had failed, leaving the caller with only a generic "Max iterations
	# reached" / "Server-set cycle detected" and no way to tell WHY without re-running with -Verbose.
	$lastServerError = $null

	while ($iteration++ -lt $maxIterations)
	{
		$setKey = ($currentServers -join ',')
		if ($visitedServerSets.Contains($setKey)) {
			$reason = "Server-set cycle detected: $setKey"
			if ($lastServerError) { $reason += " (last error: $lastServerError)" }
			$rawResult = [pscustomobject]@{
				Status = 'BailOut'
				Reason = $reason
			}
			return (ReturnResult -RawResult $rawResult)
		}
		[void]$visitedServerSets.Add($setKey)

		foreach ($server in $currentServers)
		{
			try
			{
				Write-Verbose -Message "Querying $server for $fqdn (type $TypeDisplay)"

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
						Write-Verbose -Message "Following CNAME: $fqdn -> $cnameTarget"

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
				# Moving on to the next server is correct - one unreachable nameserver must not end
				# the resolution. But a TOTALLY empty catch also swallows genuine faults (a null
				# reference, a typo in a property name), which then present as "no servers
				# responded" with nothing anywhere to say otherwise. Verbose keeps the control
				# flow identical while leaving a trail when every server appears to fail.
				$lastServerError = "$($_.Exception.Message) (from $server)"
				Write-Verbose -Message ('Resolve-DnsIterative: server query failed, trying next: {0}' -f $_.Exception.Message)
				Write-MyCatchAudit -Source 'Resolve-DnsIterative: one nameserver in the candidate set failed to query - trying the next one is correct, but this leaves a trail for the every-server-fails case' -ErrorRecord $_
			}
		}
	}

	$reason = "Max iterations ($maxIterations) reached"
	if ($lastServerError) { $reason += " (last error: $lastServerError)" }
	$rawResult = [pscustomobject]@{
		Status = 'BailOut'
		Reason = $reason
	}
	return (ReturnResult -RawResult $rawResult)
}
