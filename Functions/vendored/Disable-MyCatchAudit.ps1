# VENDORED from CommonScripts\0.2\Functions\Disable-MyCatchAudit.ps1 by Sync-SharedUtilities [SHA256 0278BD00BBF2784E2F26219BDC4D90BEFCA8BF57EFC9FE7AA41B6E0F5C541D41] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Disable-MyCatchAudit
{
	<#
		.SYNOPSIS
		Turns OFF the live console echo for Write-MyCatchAudit (the default) - capture stays on regardless.

		.DESCRIPTION
		2026-09-07: replaces the per-module Disable-VHDCatchAudit/Disable-CDCatchAudit (both retired).
		Capture into $Global:MyCatchAuditLog is unconditional and unaffected by this - see
		Enable-MyCatchAudit's own doc for why the toggle now only controls the LIVE echo tier, not
		whether something gets recorded at all. Use Show-MyCatchAuditSummary or Get-MyCatchAuditLog to
		see what was caught while this was off.

		.EXAMPLE
		Disable-MyCatchAudit
	#>
	[CmdletBinding()]
	Param ()
	$env:MyCatchAuditVerbose = $null
	Write-Output -InputObject 'Catch-audit live echo is OFF for this process (the default) - accepted catches are still captured silently. Run Show-MyCatchAuditSummary (or Get-MyCatchAuditLog) to see them, or Enable-MyCatchAudit to see them live too.'
}
