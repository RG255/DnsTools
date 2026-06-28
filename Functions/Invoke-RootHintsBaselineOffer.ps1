function Invoke-RootHintsBaselineOffer
{
	<#
		.SYNOPSIS
		If the verified root hints loaded at import differ from the trusted baseline, briefly offer to persist
		them. Interactive console only - everything else just prints a one-line notice. Never throws.

		.DESCRIPTION
		Called once at the end of module initialization. When the live (TLS-verified) root hints differ from
		the shipped baseline, a real interactive console gets a timed key prompt: press 'Y' within the timeout
		to save (which elevates via Update-DnsRootHints); Enter, any other key, or the timeout skips. Hosts that
		do not support a raw key read (the VS Code console, remoting, redirected/non-interactive input) instead
		get a single non-blocking notice. Declining or skipping is never an error.

		.PARAMETER TimeoutSeconds
		How long to wait for the key press before skipping. Default 5.
	#>
	[CmdletBinding()]
	param(
		[Int]$TimeoutSeconds = 5
	)

	if (-not (Get-Variable -Name DnsRootHintsBaselineDiffers -Scope Script -ErrorAction SilentlyContinue))
	{return}
	if (-not $script:DnsRootHintsBaselineDiffers)
	{return}

	# A timed key read only works in a real interactive console host. In the VS Code PowerShell console,
	# remoting, redirected input, or non-interactive sessions [Console]::KeyAvailable throws - detect that and
	# fall back to a non-blocking notice.
	$canPrompt = $false
	if ([Environment]::UserInteractive)
	{
		try
		{
			if (-not [Console]::IsInputRedirected)
			{
				$null = [Console]::KeyAvailable   # throws in hosts without a raw console
				$canPrompt = $true
			}
		}
		catch
		{$canPrompt = $false}
	}

	if (-not $canPrompt)
	{
		Write-Host 'DnsTools: live root hints differ from the saved baseline. Run Update-DnsRootHints (elevation required) to persist them.' -ForegroundColor DarkCyan
		return
	}

	Write-Host ''
	Write-Host 'DnsTools: the live (verified) root hints differ from the saved baseline.' -ForegroundColor Cyan
	Write-Host ("Press 'Y' within {0}s to save them to the protected baseline (elevation required). Enter / any other key / timeout = skip." -f $TimeoutSeconds) -ForegroundColor Cyan

	$doSave   = $false
	$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
	try
	{
		while ((Get-Date) -lt $deadline)
		{
			if ([Console]::KeyAvailable)
			{
				$key = [Console]::ReadKey($true)
				if ($key.Key -eq [ConsoleKey]::Y)
				{$doSave = $true}
				break
			}
			Start-Sleep -Milliseconds 50
		}
	}
	catch
	{$doSave = $false}

	Write-Host ''
	if ($doSave)
	{Update-DnsRootHints}
	else
	{Write-Host 'Skipped. Run Update-DnsRootHints later to persist the change.' -ForegroundColor DarkGray}
}
