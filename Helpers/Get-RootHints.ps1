function Get-RootHintsObject
{
	# URI to obtain the authoritative root hints file (TLS-authenticated).
	$URI_RH = 'https://www.internic.net/domain/named.root'

	# Shipped, read-only baseline that lives inside the (admin-only) module folder. Because a standard
	# user - or user-level malware - cannot write here, this is the TRUSTED offline fallback and the
	# yardstick used to sanity-check the writable runtime cache below.
	$baselineCache = Join-Path -Path $PSScriptRoot -ChildPath 'RootHints-Cache.xml'

	# Writable per-user runtime cache. Convenience only, and treated as UNTRUSTED: a user-writable file
	# could be poisoned to point iterative resolution at attacker-controlled "root" servers, so anything
	# loaded from here is filtered against the trusted baseline before it is used. Never write into the
	# admin-only module folder (that just produced an access-denied warning and persisted nothing).
	$userCacheDir = Join-Path -Path ([Environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'DnsTools'
	$userCache    = Join-Path -Path $userCacheDir -ChildPath 'RootHints-Cache.xml'

	# Session state consumed later (after functions load) by Invoke-RootHintsBaselineOffer / Update-DnsRootHints:
	# the verified result from this load and whether it differs from the trusted baseline. Set at module scope.
	$script:DnsRootHintsVerified        = $null
	$script:DnsRootHintsBaselineDiffers = $false

	# Known-good root addresses taken from the trusted baseline, used to validate the user cache.
	$getTrustedSet = {
		if (Test-Path -LiteralPath $baselineCache)
		{
			try
			{
				$b = Import-Clixml -LiteralPath $baselineCache
				return [System.Collections.Generic.HashSet[string]]::new([string[]]@($b.RootServerAddresses))
			}
			catch
			{Write-Verbose -Message "Could not read trusted root-hints baseline for validation: $($_.Exception.Message)"}
		}
		return $null
	}

	# Content equality of two root-hints objects, keyed hostname -> sorted IPs. CachedDate is deliberately
	# ignored: it advances on every fetch, so including it would flag a "change" each time. Only the actual
	# roots + addresses decide whether the set varies.
	$rootsMatch = {
		param($a, $b)
		if (-not $a -or -not $b) {return $false}
		$ma = @{}
		foreach ($e in $a.RootServers) {$ma[[string]$e.HostName] = ((@($e.IPv4, $e.IPv6) | Where-Object -FilterScript {$_} | Sort-Object) -join ',')}
		$mb = @{}
		foreach ($e in $b.RootServers) {$mb[[string]$e.HostName] = ((@($e.IPv4, $e.IPv6) | Where-Object -FilterScript {$_} | Sort-Object) -join ',')}
		if ($ma.Keys.Count -ne $mb.Keys.Count) {return $false}
		foreach ($k in $ma.Keys) {if (-not $mb.ContainsKey($k) -or $mb[$k] -ne $ma[$k]) {return $false}}
		return $true
	}

	# --- 1. Authoritative live fetch over HTTPS --------------------------------------------------
	$RHDataIn = $null
	try
	{
		$RHDataIn = -join [char[]](Invoke-WebRequest -Uri $URI_RH -UseBasicParsing).Content
	}
	catch
	{
		Write-Warning -Message "Unable to obtain root hints from: [$URI_RH]"

		# 2a. Trusted offline fallback: the admin-only shipped baseline.
		if (Test-Path -LiteralPath $baselineCache)
		{
			Write-Warning -Message "Loading root hints from trusted baseline: [$baselineCache]"
			try
			{return (Import-Clixml -LiteralPath $baselineCache)}
			catch
			{Write-Warning -Message "Failed to load baseline root hints: $($_.Exception.Message)"}
		}

		# 2b. Last resort: the writable user cache, but ONLY addresses that also appear in the trusted
		#     baseline are kept, so a poisoned cache cannot introduce new/forged root IPs. With no
		#     trusted baseline to validate against, the user cache is unverifiable and is ignored.
		if (Test-Path -LiteralPath $userCache)
		{
			$trusted = & $getTrustedSet
			if (-not $trusted -or $trusted.Count -eq 0)
			{Write-Warning -Message 'No trusted baseline to validate the user root-hints cache against - ignoring it.'}
			else
			{
				Write-Warning -Message "Loading root hints from user cache (validated): [$userCache]"
				try
				{
					$cached = Import-Clixml -LiteralPath $userCache
					$kept   = @($cached.RootServerAddresses | Where-Object -FilterScript {$trusted.Contains($_)})
					if ($kept.Count -gt 0)
					{
						$cached.RootServerAddresses = $kept
						return $cached
					}
					Write-Warning -Message 'User root-hints cache shares no addresses with the trusted baseline - discarding it.'
				}
				catch
				{Write-Warning -Message "Failed to load user root hints cache: $($_.Exception.Message)"}
			}
		}

		Write-Warning -Message 'No usable root hints available.'
		return $null
	}

	# Parse the root hints data
	# Initialise storage
	$RootServers = @()
	$RootServerMap = @{}

	# Split into lines
	$lines = $RHDataIn -split "`n" | ForEach-Object -Process {$_.Trim()}

	foreach ($line in $lines)
	{
		# Skip comments and blanks
		if ($line -match '^\s*;')
		{continue}
		if ($line -eq '')
		{continue}

		# NS record
		if ($line -match '^\.\s+\d+\s+NS\s+([A-Za-z0-9\.\-]+)\.?$')
		{
			$hn = $Matches[1].ToUpper() + '.'
			$entry = [ordered]@{
				Name     = '.'
				HostName = $hn
				IPv4     = $null
				IPv6     = $null
			}
			$RootServers += $entry
			$RootServerMap[$hn] = $entry
			continue
		}

		# IPv4 glue
		if ($line -match '^([A-Za-z0-9\.\-]+)\.?\s+\d+\s+A\s+([0-9\.]+)$')
		{
			$hn   = $Matches[1].ToUpper() + '.'
			$addr = $Matches[2]
			if ($RootServerMap.ContainsKey($hn))
			{$RootServerMap[$hn].IPv4 = $addr}
			continue
		}

		# IPv6 glue
		if ($line -match '^([A-Za-z0-9\.\-]+)\.?\s+\d+\s+AAAA\s+([0-9A-Fa-f:]+)$')
		{
			$hn   = $Matches[1].ToUpper() + '.'
			$addr = $Matches[2]
			if ($RootServerMap.ContainsKey($hn))
			{$RootServerMap[$hn].IPv6 = $addr}
			continue
		}
	}

	# Build flat list of usable IPs
	$RootServerAddresses =
	$RootServers |
	ForEach-Object -Process {
		@($_.IPv4, $_.IPv6) | Where-Object -FilterScript {$_}
	}

	# Create the result object
	$result = [pscustomobject]@{
		RootServers         = $RootServers
		RootServerAddresses = $RootServerAddresses
		CachedDate          = (Get-Date)
	}

	# Record this verified result and whether it differs from the trusted baseline (content only, timestamp
	# ignored). The module offers - later, once functions are loaded - to persist a genuine change.
	$script:DnsRootHintsVerified = $result
	if (Test-Path -LiteralPath $baselineCache)
	{
		try
		{
			$baseObj = Import-Clixml -LiteralPath $baselineCache
			if (-not (& $rootsMatch $result $baseObj)) {$script:DnsRootHintsBaselineDiffers = $true}
		}
		catch
		{Write-Verbose -Message "Could not compare against the root-hints baseline: $($_.Exception.Message)"}
	}

	# Save to the WRITABLE per-user cache (never the admin-only module folder).
	try
	{
		if (-not (Test-Path -LiteralPath $userCacheDir))
		{$null = New-Item -ItemType Directory -Path $userCacheDir -Force -ErrorAction Stop}
		$result | Export-Clixml -LiteralPath $userCache -Force
	}
	catch
	{
		Write-Warning -Message "Failed to save root hints cache: $($_.Exception.Message)"
	}

	# Return the result
	return $result
}
Get-RootHintsObject
