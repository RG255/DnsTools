# VENDORED from CommonScripts\0.2\Functions\Clear-MyFunctionTraceLog.ps1 by Sync-SharedUtilities [SHA256 3BCBC401CCA0644E85B889FF750B8C5223471D60DC2241045F772F19997376C4] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Clear-MyFunctionTraceLog
{
	<#
		.SYNOPSIS
		Archives the shared function-trace log and starts a fresh one.

		.DESCRIPTION
		2026-09-16. Mirrors Clear-MyCatchAuditLog's own shape exactly (see that function's own
		.DESCRIPTION for the full reasoning) - never deletes anything, moves the current
		FunctionTrace.log to a timestamped 'FunctionTrace-Archived-<UTC yyyyMMdd-HHmmss>.log' in the same
		folder, so a bulk clear can always be undone by hand or reviewed later. The next
		Write-MyFunctionTrace call simply recreates an empty active file via Add-Content's normal
		behaviour - nothing needs to be pre-created here.

		Named to match the existing family (Write-/Enable-/Disable-MyFunctionTrace,
		Get-MyFunctionTracePath, Format-MyFunctionTraceLine) rather than a generic "trace log" name, and
		the "Log" suffix to parallel Clear-MyCatchAuditLog precisely - the two are the same shape of
		function for sibling facilities.

		.EXAMPLE
		Enable-MyFunctionTrace -Option 1
		# ... reproduce something, read the log ...
		Clear-MyFunctionTraceLog
		# ... reproduce again with a clean log ...
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'State change (archiving the log) is the explicit purpose of this function')]
	[CmdletBinding(SupportsShouldProcess)]
	Param ()

	$Private:_path = Get-MyFunctionTracePath
	If (-not (Test-Path -LiteralPath $Private:_path -PathType Leaf))
	{ Write-Output -InputObject 'Clear-MyFunctionTraceLog: no trace log file exists yet - nothing to clear.'; return }

	$Private:_item = Get-Item -LiteralPath $Private:_path
	If ($Private:_item.Length -eq 0)
	{ Write-Output -InputObject 'Clear-MyFunctionTraceLog: the trace log is already empty.'; return }

	# 2026-09-20: a per-session file (FunctionTrace-Session-<Id>.log) keeps its id in the archive name so the
	# session is not lost; the FunctionTrace-Archived- prefix is kept so Clear-MyFunctionTraceArchive still
	# matches every archive. The shared file's archive name is unchanged.
	$Private:_suffix = ''
	If ((Split-Path -Path $Private:_path -Leaf) -match '^FunctionTrace-Session-(?<Id>.+)\.log$')
	{ $Private:_suffix = '-Session-{0}' -f $Matches['Id'] }
	$Private:_archivePath = Join-Path -Path (Split-Path -Path $Private:_path -Parent) `
		-ChildPath ('FunctionTrace-Archived-{0}{1}.log' -f ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')), $Private:_suffix)

	If ($PSCmdlet.ShouldProcess($Private:_path, 'Archive and clear the shared function-trace log'))
	{
		Try
		{
			Move-Item -LiteralPath $Private:_path -Destination $Private:_archivePath -Force -ErrorAction Stop
			Write-Output -InputObject ('Archived function-trace log to: {0}' -f $Private:_archivePath)
		}
		Catch
		{ Write-MyCatchAudit -Source 'Clear-MyFunctionTraceLog: could not archive the trace log' -ErrorRecord $_ }
	}
}
