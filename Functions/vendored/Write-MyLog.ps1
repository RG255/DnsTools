# VENDORED from CommonScripts\0.2\Functions\Write-MyLog.ps1 by Sync-SharedUtilities [SHA256 4453BC57491AB814B98F89D841479B01ADD0FA7CD55076EFC7C9E5F5C69C624B] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Write-MyLog
{
	<#
		.SYNOPSIS
		Writes a message or function call-stack entry to a log file.

		.DESCRIPTION
		Appends a timestamped message or call-stack line to the specified log file.
		Optionally mirrors output to the console. Silently skips writing if
		PathToLogFile is empty or null.

		.PARAMETER PathToLogFile
		Full path to the log file. If empty or null the function does nothing.

		.PARAMETER Message
		Text to write. A timestamp is prepended automatically.

		.PARAMETER CallStack
		Pass the output of Get-PSCallStack to write a function-trace entry instead
		of (or in addition to) a plain message.

		.PARAMETER Encoding
		File encoding. Defaults to UTF8.

		.PARAMETER Console
		If specified, also writes to the console (host) when the session is
		interactive.

		.EXAMPLE
		Write-MyLog -PathToLogFile 'C:\Logs\backup.log' -Message 'Backup started'

		.EXAMPLE
		Write-MyLog -PathToLogFile $LogFile -CallStack (Get-PSCallStack)
	#>

	[CmdletBinding(PositionalBinding = $False)]
	Param (
		[String]$PathToLogFile = '',
		[Parameter(ValueFromPipeline)]
		[String]$Message       = '',
		[Array]$CallStack      = $null,
		[String]$Encoding      = 'UTF8',
		[Switch]$Console
	)

	Process
	{
	# Nothing to do if no log path provided
	if ([string]::IsNullOrWhiteSpace($PathToLogFile))
	{ return }

	$Private:Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
	$Private:StackCount = if ($CallStack) { $CallStack.Count } else { 0 }
	$Private:DateStamp  = ('{0} Stack Count:[{1}]' -f $Private:Timestamp, $Private:StackCount)

	$Private:CallInfo = ''
	$Private:MsgInfo  = ''

	# Wrapped 2026-09-15 - same reasoning as Get-MyError.ps1's/Format-MyTextLine.ps1's own wraps: an
	# unexpected $CallStack shape (e.g. too few frames for .FunctionName[1]/.Location[1]) throwing here
	# would propagate out of what callers treat as a safe, best-effort logging call. On failure, both
	# lines are simply left blank - nothing gets logged this call, but the caller is never interrupted.
	Try
	{
		# Build call-stack trace line
		if ($CallStack)
		{
			$Private:CallInfo = ('{0} Function:[{1}] in:[{3}] Called from:[{2}] Function:[{4}]' -f
				$Private:DateStamp,
				$CallStack.FunctionName[0],
				$CallStack.Location[1],
				$CallStack.Location[0].Split(':')[0],
				$CallStack.FunctionName[1])
		}

		# Build message line
		if ($Message)
		{ $Private:MsgInfo = ('{0} {1}' -f $Private:DateStamp, $Message) }
	}
	Catch
	{
		Write-MyCatchAudit -Source 'Write-MyLog: internal failure building the log line(s)' -ErrorRecord $_
	}

	# Write to file
	try
	{
		if ($Private:CallInfo)
		{ Out-File -Encoding $Encoding -FilePath $PathToLogFile -Append -InputObject $Private:CallInfo }
		if ($Private:MsgInfo)
		{ Out-File -Encoding $Encoding -FilePath $PathToLogFile -Append -InputObject $Private:MsgInfo }
	}
	catch
	{
		Write-Warning ('Write-MyLog: could not write to [{0}]: {1}' -f $PathToLogFile, $_.Exception.Message)
		Write-MyCatchAudit -Source 'Write-MyLog: write to the optional diagnostic log file - a logging failure must never take down the operation it is observing' -ErrorRecord $_
	}

	# Mirror to console if requested and session is interactive. Wrapped 2026-09-15 - Write-Host can
	# genuinely throw in some non-interactive/redirected hosting scenarios (the same class of risk
	# Write-MyCatchAudit's own doc calls out for [Console]::Error.WriteLine) - a console-mirroring
	# convenience must never be able to take down the caller.
	Try
	{
		if ($Console.IsPresent -and [Environment]::UserInteractive)
		{
			if ($Private:CallInfo)
			{ Write-Host -Object $Private:CallInfo -ForegroundColor Cyan }
			if ($Private:MsgInfo)
			{ Write-Host -Object $Private:MsgInfo  -ForegroundColor Magenta }
		}
	}
	Catch
	{
		Write-MyCatchAudit -Source 'Write-MyLog: mirror the log line(s) to the console' -ErrorRecord $_
	}
	} # end Process
}
