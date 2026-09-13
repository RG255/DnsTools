# VENDORED from CommonScripts\0.2\Functions\Enable-MyCatchAudit.ps1 by Sync-SharedUtilities [SHA256 3BF7B7A17FAE69D0CF3121F78F4B026689FE7E5CB2477E4D4E96CA922B3614CC] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Enable-MyCatchAudit
{
	<#
		.SYNOPSIS
		Turns ON the live console echo for Write-MyCatchAudit - capture itself is always on regardless.

		.DESCRIPTION
		2026-09-07: replaces the per-module Enable-VHDCatchAudit/Enable-CDCatchAudit (both retired).
		Capture into $Global:MyCatchAuditLog is unconditional now, so this no longer controls whether
		something gets recorded at all - only whether Write-MyCatchAudit ALSO prints a friendly report
		live, via $env:MyCatchAuditVerbose (one shared env var, not a per-module one - the actual reason
		the old module-specific versions no longer need to exist separately). Use this while actively
		debugging something right now; otherwise call Show-MyCatchAuditSummary (or Get-MyCatchAuditLog
		directly) at the end of a run instead - nothing is ever lost by leaving this off.

		Process-scoped on purpose: a GUI/CLI client and any elevated server process it talks to are
		SEPARATE processes, so this call in one does not affect the other.

		.EXAMPLE
		Enable-MyCatchAudit
		# ... reproduce the issue - each accepted catch now also prints live ...
		Disable-MyCatchAudit
	#>
	[CmdletBinding()]
	Param ()
	$env:MyCatchAuditVerbose = '1'
	Write-Output -InputObject 'Catch-audit live echo is ON for this process - Write-MyCatchAudit will also print each accepted catch as it happens. Capture into Get-MyCatchAuditLog happens either way. Run Disable-MyCatchAudit to turn the live echo back off.'
}
