# VENDORED from CommonScripts\0.2\Functions\Clear-MyFunctionTraceArchive.ps1 by Sync-SharedUtilities [SHA256 B3D816F9314F7B48422EFF273F9E08D303AFB072B24802C91EBDF324F3687A44] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Clear-MyFunctionTraceArchive
{
	<#
		.SYNOPSIS
		Prunes old archived function-trace logs left behind by Clear-MyFunctionTraceLog.

		.DESCRIPTION
		2026-09-16. Mirrors Clear-MyCatchAuditArchive exactly - see that function's own .DESCRIPTION for
		the full reasoning. Clear-MyFunctionTraceLog archives the active trace log to a timestamped
		'FunctionTrace-Archived-<UTC yyyyMMdd-HHmmss>.log' file every time it runs, and nothing prunes
		those afterward. Wraps Invoke-FileManagement pointed at that archive pattern instead.

		.PARAMETER NumberOfFiles
		Keep no more than this many archived logs. Default: 10. Pass 0 to disable this rule.

		.PARAMETER DaysOld
		Delete archived logs older than this many days. Default: 90. Pass 0 to disable this rule. Also
		applied (age only, never a count) to per-session trace files FunctionTrace-Session-*.log by
		last-write time, so a file a window has written to recently is never deleted.

		.EXAMPLE
		Clear-MyFunctionTraceArchive
		Keeps the 10 most recent archives, deletes anything older than 90 days.
	#>
	[CmdletBinding()]
	Param (
		[ValidateRange(0, [int]::MaxValue)]
		[int]$NumberOfFiles = 10,
		[ValidateRange(0, [int]::MaxValue)]
		[int]$DaysOld = 90
	)

	If ((1 -band ($env:MyFunctionTraceEnabled -as [Int])) -and (Get-Command -Name Write-MyFunctionTrace -ErrorAction SilentlyContinue)) { Write-MyFunctionTrace }

	If ($NumberOfFiles -le 0 -and $DaysOld -le 0)
	{ Write-Output -InputObject 'Clear-MyFunctionTraceArchive: both -NumberOfFiles and -DaysOld are 0 - nothing to do.'; return }

	Try
	{
		$Private:_folder = Split-Path -Path (Get-MyFunctionTracePath) -Parent
		$Private:_pattern = Join-Path -Path $Private:_folder -ChildPath 'FunctionTrace-Archived-*.log'

		If (-not (Get-ChildItem -Path $Private:_pattern -ErrorAction SilentlyContinue))
		{ Write-Output -InputObject 'Clear-MyFunctionTraceArchive: no archived logs exist yet - nothing to prune.' }
		Else
		{ Invoke-FileManagement -FilePath $Private:_pattern -NumberOfFiles $NumberOfFiles -DaysOld $DaysOld }

		# 2026-09-20: per-session trace files (FunctionTrace-Session-<Id>.log, one per PowerShell window)
		# also accumulate. AGE rule only, deliberately: Invoke-FileManagement's count rules order files by
		# NAME, which for a random session id says nothing about which file is oldest or still in use, so
		# a count rule could delete a live window's file. The age rule uses LastWriteTime, so a file any
		# window has written to recently is never touched.
		$Private:_sessionPattern = Join-Path -Path $Private:_folder -ChildPath 'FunctionTrace-Session-*.log'
		If ($DaysOld -gt 0 -and (Get-ChildItem -Path $Private:_sessionPattern -ErrorAction SilentlyContinue))
		{ Invoke-FileManagement -FilePath $Private:_sessionPattern -DaysOld $DaysOld }
	}
	Catch
	{ Write-MyCatchAudit -Source 'Clear-MyFunctionTraceArchive: failed to prune archived function-trace logs' -ErrorRecord $_ }
}
