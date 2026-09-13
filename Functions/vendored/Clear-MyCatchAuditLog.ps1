# VENDORED from CommonScripts\0.2\Functions\Clear-MyCatchAuditLog.ps1 by Sync-SharedUtilities [SHA256 9C32C77CC613B1D46C11BB6B70CA5C329ECF59B6C55148DAC629DBA654E120D0] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Clear-MyCatchAuditLog
{
	<#
		.SYNOPSIS
		Archives the entire PERSISTED catch-audit log and starts a fresh one - the "I have reviewed
		everything up to now" bulk action.

		.DESCRIPTION
		2026-09-10. Never deletes anything - Moves the current CatchAudit.jsonl to a timestamped
		'CatchAudit-Archived-<UTC yyyyMMdd-HHmmss>.jsonl' in the same folder, so a bulk clear can always
		be un-done by hand (rename it back) or reviewed later. The next Write-MyCatchAudit call simply
		recreates an empty active file via Add-Content's normal behaviour - nothing needs to be
		pre-created here.

		Use this when you have reviewed the whole log (e.g. via Show-MyCatchAuditSummary -Persisted) and
		accept everything in it. To resolve only SOME entries and leave the rest pending, use
		Invoke-MyCatchAuditTriage instead - that removes individually-chosen entries from the active
		file rather than archiving the whole thing at once.

		Does not touch the in-memory $Global:MyCatchAuditLog (Get-MyCatchAuditLog -Clear does that) -
		the two are deliberately separate stores answering different questions (this process vs ever).

		.EXAMPLE
		Show-MyCatchAuditSummary -Persisted
		# ... review it, decide everything in it is understood/accepted ...
		Clear-MyCatchAuditLog
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'State change (archiving the log) is the explicit purpose of this function')]
	[CmdletBinding(SupportsShouldProcess)]
	Param ()

	$Private:_path = Get-MyCatchAuditPersistPath
	If (-not (Test-Path -LiteralPath $Private:_path -PathType Leaf))
	{ Write-Output -InputObject 'Clear-MyCatchAuditLog: no persisted log file exists yet - nothing to clear.'; return }

	$Private:_item = Get-Item -LiteralPath $Private:_path
	If ($Private:_item.Length -eq 0)
	{ Write-Output -InputObject 'Clear-MyCatchAuditLog: the persisted log is already empty.'; return }

	$Private:_archivePath = Join-Path -Path (Split-Path -Path $Private:_path -Parent) `
		-ChildPath ('CatchAudit-Archived-{0}.jsonl' -f ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')))

	If ($PSCmdlet.ShouldProcess($Private:_path, 'Archive and clear the persisted catch-audit log'))
	{
		Try
		{
			Move-Item -LiteralPath $Private:_path -Destination $Private:_archivePath -Force -ErrorAction Stop
			Write-Output -InputObject ('Archived persisted catch-audit log to: {0}' -f $Private:_archivePath)
		}
		Catch
		{ Write-Warning -Message ('Clear-MyCatchAuditLog: could not archive the log: {0}' -f $_.Exception.Message) }
	}
}
