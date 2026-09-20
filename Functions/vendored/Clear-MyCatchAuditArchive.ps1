# VENDORED from CommonScripts\0.2\Functions\Clear-MyCatchAuditArchive.ps1 by Sync-SharedUtilities [SHA256 0FBF3F81251BCCD454A326B81B632834CB259A43E4D0396189CCF222698042F4] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Clear-MyCatchAuditArchive
{
	<#
		.SYNOPSIS
		Prunes old archived catch-audit logs left behind by Clear-MyCatchAuditLog.

		.DESCRIPTION
		2026-09-16. Clear-MyCatchAuditLog archives the active persisted log to a timestamped
		'CatchAudit-Archived-<UTC yyyyMMdd-HHmmss>.jsonl' file every time it runs, and nothing ever
		prunes those archives afterward - left alone, they accumulate indefinitely. This wraps the
		already-shared Invoke-FileManagement (age/count file retention, used the same way by Macrium's
		own log rotation) pointed at that archive pattern, so pruning is one named call instead of
		callers having to remember Invoke-FileManagement's own parameter shape each time.

		Default rule is Invoke-FileManagement's combined "NumberAndDays": keep the -NumberOfFiles most
		recent archives AND delete anything older than -DaysOld, whichever is more aggressive for a
		given file. Pass 0 for either to disable that half of the rule (matches Invoke-FileManagement's
		own convention).

		.PARAMETER NumberOfFiles
		Keep no more than this many archived logs. Default: 10. Pass 0 to disable this rule.

		.PARAMETER DaysOld
		Delete archived logs older than this many days. Default: 90. Pass 0 to disable this rule.

		.EXAMPLE
		Clear-MyCatchAuditArchive
		Keeps the 10 most recent archives, deletes anything older than 90 days.

		.EXAMPLE
		Clear-MyCatchAuditArchive -NumberOfFiles 0 -DaysOld 30
		Age-only rule: delete every archive older than 30 days, regardless of count.
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
	{ Write-Output -InputObject 'Clear-MyCatchAuditArchive: both -NumberOfFiles and -DaysOld are 0 - nothing to do.'; return }

	Try
	{
		$Private:_folder = Split-Path -Path (Get-MyCatchAuditPersistPath) -Parent
		$Private:_pattern = Join-Path -Path $Private:_folder -ChildPath 'CatchAudit-Archived-*.jsonl'

		If (-not (Get-ChildItem -Path $Private:_pattern -ErrorAction SilentlyContinue))
		{ Write-Output -InputObject 'Clear-MyCatchAuditArchive: no archived logs exist yet - nothing to prune.'; return }

		Invoke-FileManagement -FilePath $Private:_pattern -NumberOfFiles $NumberOfFiles -DaysOld $DaysOld
	}
	Catch
	{ Write-MyCatchAudit -Source 'Clear-MyCatchAuditArchive: failed to prune archived catch-audit logs' -ErrorRecord $_ }
}
