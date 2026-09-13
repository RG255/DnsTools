# VENDORED from CommonScripts\0.2\Functions\Get-MyCatchAuditLog.ps1 by Sync-SharedUtilities [SHA256 3F4774D6DD2DBF0952B691C520DF795B0B35E245F41D85E9CFC9E7B5BD79B525] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Get-MyCatchAuditLog
{
	<#
		.SYNOPSIS
		Returns catch-audit entries - either what THIS PROCESS has captured so far (default), or the
		full PERSISTED log that survives across process restarts.

		.DESCRIPTION
		2026-09-07: the read-side of the always-on capture $Global:MyCatchAuditLog - see
		Write-MyCatchAudit's own doc for why capture is unconditional and shared across every module in
		the process rather than per-module. Returns an empty array (never $null) when nothing has been
		captured yet, so a caller can always safely check `.Count` without a null-guard.

		2026-09-10: added -Persisted. The default (in-memory) view is lost the moment the process ends -
		closing the window or a crash takes it with it, with no trace. -Persisted instead reads the
		durable on-disk mirror (see Get-MyCatchAuditPersistPath), which is written alongside the
		in-memory capture on every Write-MyCatchAudit call and survives independently of any one
		process. Use -Persisted to answer "did ANYTHING get caught, possibly in a session that has
		already ended" - the question the in-memory view can never answer after the fact.

		.PARAMETER Clear
		Default (in-memory) mode only: also empties the in-memory log after returning it - use for "what
		happened since I last checked, this process." Has no effect combined with -Persisted - use
		Clear-MyCatchAuditLog (bulk archive-everything) or Invoke-MyCatchAuditTriage (per-entry resolve)
		to remove PERSISTED entries instead, since "just wipe it" is a much bigger, less reversible
		action for state that outlives this one process.

		.PARAMETER Persisted
		Read the durable, cross-process, cross-module log from disk instead of this process's in-memory
		one. Malformed lines (a write interrupted mid-append by a crash - possible only for the LAST
		line, since JSON Lines is append-only) are silently skipped rather than failing the whole read.

		.EXAMPLE
		Get-MyCatchAuditLog | Group-Object ExceptionType | Sort-Object Count -Descending
		See which exception types are recurring across everything caught so far this process.

		.EXAMPLE
		Get-MyCatchAuditLog -Persisted | Sort-Object Timestamp -Descending | Select-Object -First 20
		The 20 most recent entries ever recorded, regardless of which process/session caught them.

		.EXAMPLE
		Get-MyCatchAuditLog -Clear | Export-Csv -Path 'C:\Temp\catch-audit.csv' -NoTypeInformation
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
		Justification = 'Deliberately process-wide, not per-module - $Global:MyCatchAuditLog is the shared always-on capture every module''s Write-MyCatchAudit writes into, by design (see this function''s own DESCRIPTION).')]
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	Param ([Switch]$Clear, [Switch]$Persisted)

	If ($Persisted)
	{
		$Private:_path = Get-MyCatchAuditPersistPath
		If (-not (Test-Path -LiteralPath $Private:_path -PathType Leaf)) { return @() }
		Try
		{
			return @(Get-Content -LiteralPath $Private:_path -ErrorAction Stop |
					Where-Object { $_ } |
					ForEach-Object {
						Try { $_ | ConvertFrom-Json -ErrorAction Stop }
						# SILENT-OK: a malformed line (only ever possible for the last one, if a crash landed
						# mid-write to an append-only file) is skipped rather than failing the whole read -
						# the surrounding Where-Object { $_ } drops the resulting $null, same as an empty line.
						Catch { $null }
					} |
					Where-Object { $_ })
		}
		Catch { return @() }
	}

	$Private:_result = If ($Global:MyCatchAuditLog) { $Global:MyCatchAuditLog.ToArray() } Else { @() }
	If ($Clear -and $Global:MyCatchAuditLog) { $Global:MyCatchAuditLog.Clear() }
	return $Private:_result
}
