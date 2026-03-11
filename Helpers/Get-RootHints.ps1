function Get-RootHintsObject
{
	# URI to obtain the root hints file
	$URI_RH = 'https://www.internic.net/domain/named.root'

	# Cache file path
	$cacheFile = Join-Path -Path $PSScriptRoot -ChildPath 'RootHints-Cache.xml'

	# Try to fetch from internet
	$RHDataIn = $null
	try
	{
		$RHDataIn = -join [char[]](Invoke-WebRequest -Uri $URI_RH -UseBasicParsing).Content
	}
	catch
	{
		Write-Warning -Message "Unable to obtain root hints from: [$URI_RH]"

		# Try to load from cache
		if (Test-Path -Path $cacheFile)
		{
			Write-Warning -Message "Loading root hints from cache: [$cacheFile]"
			try
			{
				$cachedData = Import-Clixml -Path $cacheFile
				return $cachedData
			}
			catch
			{
				Write-Warning -Message "Failed to load cached root hints: $($_.Exception.Message)"
				return $null
			}
		}
		else
		{
			Write-Warning -Message "No cached root hints available"
			return $null
		}
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

	# Save to cache
	try
	{
		$result | Export-Clixml -Path $cacheFile -Force
	}
	catch
	{
		Write-Warning -Message "Failed to save root hints cache: $($_.Exception.Message)"
	}

	# Return the result
	return $result
}
Get-RootHintsObject