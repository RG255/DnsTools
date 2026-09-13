# VENDORED from CommonScripts\0.2\Functions\Show-MyCatchAuditSummary.ps1 by Sync-SharedUtilities [SHA256 F8213E8DB30D3CFE36ACC4F654F583A21686C42D445CD86C575DBE4ECA71606D] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Show-MyCatchAuditSummary
{
	<#
		.SYNOPSIS
		Prints a short, grouped summary of what Write-MyCatchAudit caught - this process only (default),
		or the full PERSISTED log that survives across process restarts.

		.DESCRIPTION
		2026-09-07: since capture is always on (see Write-MyCatchAudit), a run can complete with real
		captured entries that nobody happened to be watching for live. This is the intended place to
		check at the natural end of any CLI script/orchestrator (e.g. as the last step of
		Invoke-ModuleReleaseChecks.ps1) - prints nothing at all on a clean run (nothing was caught), or a
		short one-block summary grouped by ExceptionType (count + one representative Source/Message per
		type) when something was. Deliberately terse - this is a "go look closer" signal, not the full
		diagnostic dump Get-MyError -Return already provides for deep triage.

		2026-09-10: added -Persisted, which answers the gap this doc used to flag as unsolved -
		"a GUI wanting to show 'something was caught last time you ran this' across process launches" -
		by reading the durable on-disk mirror instead of this process's in-memory list. Use this after
		Show-MyCatchAuditPendingNotice (fired automatically at module init) tells you something is
		pending, to see what it actually is before deciding whether to Invoke-MyCatchAuditTriage or
		Clear-MyCatchAuditLog.

		.PARAMETER Clear
		Default (in-memory) mode only: also empties the log after reporting it. No effect combined with
		-Persisted - see Get-MyCatchAuditLog -Persisted's own doc for why persisted entries are removed
		through Invoke-MyCatchAuditTriage/Clear-MyCatchAuditLog instead, never through this switch.

		.PARAMETER Persisted
		Report on the durable, cross-process, cross-module log from disk instead of this process's
		in-memory one.

		.EXAMPLE
		Show-MyCatchAuditSummary
		# prints nothing if nothing was caught THIS PROCESS; a short grouped block otherwise

		.EXAMPLE
		Show-MyCatchAuditSummary -Persisted
		# same shape, but across every process that has ever run since the log was last cleared/triaged

		.EXAMPLE
		Show-MyCatchAuditSummary -Clear
		# same, then empties the in-memory log so the next run/segment starts clean
	#>
	[CmdletBinding()]
	Param ([Switch]$Clear, [Switch]$Persisted)

	$Private:_log = If ($Persisted) { Get-MyCatchAuditLog -Persisted } Else { Get-MyCatchAuditLog -Clear:$Clear }
	If (-not $Private:_log -or $Private:_log.Count -eq 0) { return }

	Write-Output -InputObject ('{0} unexpected-but-accepted issue(s) {1}:' -f $Private:_log.Count, $(If ($Persisted) { 'are recorded in the persisted log' } Else { 'were caught during this run' }))
	# Grouped by (ExceptionType, Source), not ExceptionType alone (2026-09-10 fix) - a single CLR
	# exception type can cover many genuinely different catch sites, and the old grouping picked
	# ONE arbitrary Source/Message as "the" example for the whole type, silently hiding any others
	# sharing that type. Message is truncated and whitespace-collapsed for this terse view - it is
	# often a multi-line diagnostic dump (icacls output, a full Get-MyError block) that reads as an
	# unreadable wall of text on one console line; Get-MyCatchAuditLog still returns it in full.
	$Private:_maxMessageLength = 100
	$Private:_groups = $Private:_log | Group-Object -Property ExceptionType, Source
	ForEach ($Private:_g in $Private:_groups)
	{
		$Private:_example = $Private:_g.Group[0]
		$Private:_shortType = ($Private:_example.ExceptionType -split '\.')[-1]
		$Private:_flatMessage = ($Private:_example.Message -replace '\s+', ' ').Trim()
		If ($Private:_flatMessage.Length -gt $Private:_maxMessageLength)
		{ $Private:_flatMessage = $Private:_flatMessage.Substring(0, $Private:_maxMessageLength) + '...' }
		Write-Output -InputObject ('  {0} x{1} - {2}' -f $Private:_shortType, $Private:_g.Count, $Private:_example.Source)
		Write-Output -InputObject ('      {0}' -f $Private:_flatMessage)
	}
	If ($Persisted)
	{ Write-Output -InputObject 'Run Get-MyCatchAuditLog -Persisted for full detail, Invoke-MyCatchAuditTriage to resolve individually, or Clear-MyCatchAuditLog to archive all of it.' }
	Else
	{ Write-Output -InputObject 'Run Get-MyCatchAuditLog for full detail on each one.' }
}
