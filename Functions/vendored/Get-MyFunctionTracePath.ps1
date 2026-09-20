# VENDORED from CommonScripts\0.2\Functions\Get-MyFunctionTracePath.ps1 by Sync-SharedUtilities [SHA256 347F972823012A17B70C48E5F7F3386EA49FE643A7A12E90AEA907A3FE713441] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Get-MyFunctionTracePath
{
	<#
		.SYNOPSIS
		Internal: resolves the shared, cross-process, cross-module function-trace log path, creating its
		folder if necessary.

		.DESCRIPTION
		2026-09-15. Mirrors Get-MyCatchAuditPersistPath.ps1's exact shape - one shared file for every
		module on the machine, under $env:ProgramData (not %LOCALAPPDATA%) because function tracing spans
		both elevated and non-elevated processes, sometimes under genuinely different accounts (a NamedPipe
		elevated server is a separate process from its GUI/CLI caller) - unlike a per-user path, this
		location is the same file regardless of which account writes to it.

		Not exported - internal plumbing shared by Write-MyFunctionTrace (writer) and Get-MyError's
		trace-mirroring addition (writer), so both agree on exactly one path with no risk of drift between
		a hand-typed copy in each.

		The folder-creation catch below is deliberately silent, same reasoning as
		Get-MyCatchAuditPersistPath's own: best-effort, genuinely benign either way, and every actual
		caller already handles a still-missing folder correctly on its own (Add-Content failing against a
		missing folder surfaces one level up, at the caller, which already has its own recursion-safe
		error handling).

		2026-09-20: when $env:MyFunctionTraceSessionId is set (Enable-MyFunctionTrace now sets one) the file
		is FunctionTrace-Session-<Id>.log, one per PowerShell window, and a NamedPipe client and its own
		elevated server share it via the id. With no id set it is the shared FunctionTrace.log.

		.OUTPUTS
		[String] full path to the log file (the file itself may not exist yet - callers create it by
		writing, per Add-Content's normal behaviour).
	#>
	[CmdletBinding()]
	[OutputType([String])]
	Param ()

	$Private:_folder = Join-Path -Path $env:ProgramData -ChildPath 'FunctionTrace'
	If (-not (Test-Path -LiteralPath $Private:_folder -PathType Container))
	{
		Try { $null = New-Item -Path $Private:_folder -ItemType Directory -Force -ErrorAction Stop }
		# SILENT-OK: best-effort folder creation - see this function's own .DESCRIPTION.
		Catch { $null = $_ }
	}

	# 2026-09-20: one file per session id, so two PowerShell windows tracing at once do not interleave.
	# The id arrives from an environment variable (and, for an elevated NamedPipe server, from serialized
	# ServerClientParams), so it is reduced to safe filename characters first - it must never be able to
	# add a path separator or ".." to where this file lands. No id set = the shared file, as before.
	$Private:_id = ([String]$env:MyFunctionTraceSessionId) -replace '[^A-Za-z0-9_-]', ''
	If ($Private:_id.Length -gt 32) { $Private:_id = $Private:_id.Substring(0, 32) }
	$Private:_name = If ($Private:_id) { 'FunctionTrace-Session-{0}.log' -f $Private:_id } Else { 'FunctionTrace.log' }
	Join-Path -Path $Private:_folder -ChildPath $Private:_name
}
