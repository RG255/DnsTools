function Update-DnsRootHints
{
	<#
		.SYNOPSIS
		Persists the current verified root hints to the protected (admin-only) baseline, elevating once.

		.DESCRIPTION
		The iterative resolver bootstraps from RootServerAddresses, loaded at import from a live, TLS-verified
		fetch of named.root (it falls back to the shipped baseline when offline). When the live fetch differs
		from that baseline, this command writes the verified set over the baseline in the deployed module
		folder(s). Those folders are admin-only, so it elevates via Start-Process -Verb RunAs.

		Declining the UAC prompt, or running where elevation is unavailable, is NOT treated as an error:
		nothing is written and the session keeps using the verified set it already loaded.

		By default it saves the verified set captured at import; -Refresh re-fetches named.root first.

		.PARAMETER Refresh
		Re-fetch named.root before saving instead of using the verified set captured at import.

		.EXAMPLE
		Update-DnsRootHints
		Saves the verified root hints from this session to the protected baseline (one UAC prompt).
	#>
	[CmdletBinding()]
	param(
		[Switch]$Refresh
	)

	$verified = $null
	if (-not $Refresh -and (Get-Variable -Name DnsRootHintsVerified -Scope Script -ErrorAction SilentlyContinue))
	{$verified = $script:DnsRootHintsVerified}

	if (-not $verified)
	{
		try
		{$verified = . (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Helpers\Get-RootHints.ps1')}
		catch
		{Write-Warning -Message "Could not obtain verified root hints: $($_.Exception.Message)"; return}
	}
	if (-not $verified -or -not $verified.RootServerAddresses)
	{Write-Warning -Message 'No verified root hints available to save.'; return}

	# Target baseline(s): this module's deployed Helpers folder, plus the sibling edition's if present, so the
	# PS5 and PS7 copies stay consistent.
	$modRoot = Split-Path -Path $PSScriptRoot -Parent
	$targets = [System.Collections.Generic.List[string]]::new()
	$targets.Add((Join-Path -Path $modRoot -ChildPath 'Helpers\RootHints-Cache.xml'))
	$sibRoot = $null
	if ($modRoot -match '\\PowerShell\\Modules\\')
	{$sibRoot = $modRoot -replace '\\PowerShell\\Modules\\', '\WindowsPowerShell\Modules\'}
	elseif ($modRoot -match '\\WindowsPowerShell\\Modules\\')
	{$sibRoot = $modRoot -replace '\\WindowsPowerShell\\Modules\\', '\PowerShell\Modules\'}
	if ($sibRoot -and (Test-Path -LiteralPath (Join-Path -Path $sibRoot -ChildPath 'Helpers')))
	{$targets.Add((Join-Path -Path $sibRoot -ChildPath 'Helpers\RootHints-Cache.xml'))}

	# Stage the verified object to a temp clixml, then copy it over each baseline from an elevated worker.
	$tmpDir = 'C:\Temp'
	if (-not (Test-Path -LiteralPath $tmpDir))
	{$null = New-Item -ItemType Directory -Path $tmpDir -Force}
	$stamp      = [guid]::NewGuid().ToString('N')
	$stageFile  = Join-Path -Path $tmpDir -ChildPath ('DnsRootHints-{0}.xml' -f $stamp)
	$workScript = Join-Path -Path $tmpDir -ChildPath ('DnsRootHints-{0}.ps1' -f $stamp)
	$verified | Export-Clixml -LiteralPath $stageFile -Force

	$body = New-Object -TypeName System.Collections.Generic.List[string]
	$body.Add('$ErrorActionPreference = ''Stop''')
	foreach ($t in $targets)
	{$body.Add(('Copy-Item -LiteralPath "{0}" -Destination "{1}" -Force' -f $stageFile, $t))}
	Set-Content -LiteralPath $workScript -Value $body -Force

	$hostCmd = Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
	$hostExe = if ($hostCmd) {$hostCmd.Source} else {'powershell.exe'}
	try
	{
		$proc = Start-Process -FilePath $hostExe -Verb RunAs -WindowStyle Hidden -PassThru -Wait `
			-ArgumentList @('-NoProfile', '-ExecutionPolicy', 'RemoteSigned', '-File', $workScript) -ErrorAction Stop
		if ($proc.ExitCode -eq 0)
		{
			Write-Host ('Root hints baseline updated ({0} location(s)).' -f $targets.Count) -ForegroundColor Green
			$script:DnsRootHintsBaselineDiffers = $false
		}
		else
		{Write-Warning -Message ('Elevated write returned exit code {0} - baseline may not have been updated.' -f $proc.ExitCode)}
	}
	catch
	{
		# UAC declined or elevation unavailable - explicitly NOT an error, by design.
		Write-Host 'Root hints baseline not updated (elevation was declined or unavailable).' -ForegroundColor DarkGray
	}
	finally
	{Remove-Item -LiteralPath $stageFile, $workScript -Force -ErrorAction SilentlyContinue}
}
