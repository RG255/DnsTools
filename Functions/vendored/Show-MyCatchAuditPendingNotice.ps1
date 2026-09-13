# VENDORED from CommonScripts\0.2\Functions\Show-MyCatchAuditPendingNotice.ps1 by Sync-SharedUtilities [SHA256 F6CD95045C3E026D851023792EF6EEE361D955452047B405F15B0019B84C7EA3] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Show-MyCatchAuditPendingNotice
{
	<#
		.SYNOPSIS
		Prints a one-line notice if the PERSISTED catch-audit log has any entries - meant to be called
		automatically, once, from every vendoring module's own initialization.

		.DESCRIPTION
		2026-09-10. The whole point of persisting catch-audit entries to disk (see
		Get-MyCatchAuditPersistPath) is that closing the window, or a crash, must never silently lose
		the fact that something was caught - but persistence alone still requires someone to think to
		go and check. This closes that gap at the most natural trigger point available: every one of
		the 7 modules that vendor this file calls it once at the end of their own root .psm1, right
		after everything else has finished loading - so the moment ANY of them is imported (explicitly,
		or auto-loaded on first use of one of their commands), a pending entry surfaces without the
		user needing to remember to run anything.

		ONCE PER PROCESS, not once per module: a session that loads several of these modules (or
		re-imports one with -Force during development, which happens constantly in this repo) would
		otherwise repeat the notice every time. Guarded via $Global:MyCatchAuditNoticeShown - whichever
		module happens to load first in a given process shows it (if there is anything to show) and
		sets the flag; every later module's own call in that same process sees the flag and returns
		immediately, silently.

		Deliberately does NOT cover a genuinely headless run (e.g. a Task Scheduler job with no
		interactive console) - Write-Warning/Write-Output there go nowhere anyone will ever see. That
		is a real, separate gap (an unattended run needs a durable, out-of-process signal - the Windows
		Event Log is the natural fit, not built here yet) - out of scope for this pass, which only
		solves "I closed the window/it crashed before I thought to check."

		Never opens, imports, or otherwise triggers anything - a pure read of the persisted file, so
		calling this from a module's own init can never itself cause a failure loop.

		.EXAMPLE
		Show-MyCatchAuditPendingNotice
		# prints nothing if the persisted log is empty, or already reported this process; otherwise a
		# one-line count + hint to run Show-MyCatchAuditSummary -Persisted
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
		Justification = 'Deliberately process-wide - the "show this once per process, not once per module" guard only works if every vendoring module shares the same flag (see this function''s own DESCRIPTION).')]
	[CmdletBinding()]
	Param ()

	If ($Global:MyCatchAuditNoticeShown) { return }

	$Private:_path = Get-MyCatchAuditPersistPath
	If (-not (Test-Path -LiteralPath $Private:_path -PathType Leaf)) { return }

	Try { $Private:_lineCount = @(Get-Content -LiteralPath $Private:_path -ErrorAction Stop | Where-Object { $_ }).Count }
	Catch { return }
	If ($Private:_lineCount -eq 0) { return }

	# Set the flag ONLY once there is something real to report - an unreadable/empty file should not
	# permanently suppress a LATER module's check within the same process (e.g. the file could still be
	# mid-write by another process the first time this ran).
	$Global:MyCatchAuditNoticeShown = $true
	Write-Warning -Message ('{0} unresolved catch-audit entr{1} recorded (possibly from an earlier session) - run Show-MyCatchAuditSummary -Persisted to review, then Invoke-MyCatchAuditTriage or Clear-MyCatchAuditLog once triaged.' -f `
		$Private:_lineCount, $(If ($Private:_lineCount -eq 1) { 'y' } Else { 'ies' }))
}
