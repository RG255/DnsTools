# VENDORED from CommonScripts\0.2\Functions\Get-MyCatchAuditPersistPath.ps1 by Sync-SharedUtilities [SHA256 EA28DA542AEC4B9D203335090F2001CBF8495FB471E2FCBBBD072A90CACCC501] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Get-MyCatchAuditPersistPath
{
	<#
		.SYNOPSIS
		Internal: resolves the shared, cross-process, cross-module PERSISTED catch-audit log path,
		creating its folder if necessary.

		.DESCRIPTION
		2026-09-10. $Global:MyCatchAuditLog (see Write-MyCatchAudit) is pure in-memory state - closing
		the window, or the process crashing, loses it completely with no trace. This adds a durable
		on-disk mirror so nothing caught is ever lost just because nobody happened to check before the
		process ended. One shared file for every module on the machine, matching Write-MyCatchAudit's
		own "one shared trail across every module in the process" reasoning - just extended across
		process lifetimes too.

		Location: $env:ProgramData\CatchAudit\CatchAudit.jsonl - ProgramData because catch-audit calls
		happen from both elevated and non-elevated processes (sometimes under genuinely different
		accounts - see the whole AdminAccess/separate-elevation-account thread in VHDTools), and unlike
		a per-user path (%LOCALAPPDATA%) this location is the same file regardless of which account
		writes to it. Matches the existing convention for other shared, cross-account module state
		(VHDTools' Settings.psd1, VaultTools' KeyVault) - both already live under $env:ProgramData.

		Format: JSON Lines (one compact JSON object per line, append-only) - crash-safe by construction
		(never a read-modify-write of the whole file, so a write in progress at the moment of a crash
		can corrupt at most the one line being appended, never anything already durable), and trivially
		parseable a line at a time.

		Not exported - internal plumbing shared by Write-MyCatchAudit (writer),
		Get-MyCatchAuditLog -Persisted (reader), Clear-MyCatchAuditLog (archiver), and
		Show-MyCatchAuditPendingNotice (module-init check), so all four agree on exactly one path with
		no risk of drift between a hand-typed copy in each.

		The folder-creation catch below is deliberately silent and NOT routed through
		Write-MyCatchAudit: folder creation is best-effort and genuinely benign either way - this
		function still returns the path exactly as it would on success, and every actual caller already
		handles that outcome correctly on its own (Write-MyCatchAudit's own persist Try/Catch will then
		hit Add-Content failing against the missing folder and report THAT, with its own call-stack
		recursion guard; every reader already treats "file not found" as "nothing captured yet", which
		is exactly true here). Nothing is lost by staying silent at this one specific point - the
		failure surfaces one level up regardless.

		.OUTPUTS
		[String] full path to the JSONL file (the file itself may not exist yet - callers create it by
		writing, per Add-Content's normal behaviour).
	#>
	[CmdletBinding()]
	[OutputType([String])]
	Param ()

	$Private:_folder = Join-Path -Path $env:ProgramData -ChildPath 'CatchAudit'
	If (-not (Test-Path -LiteralPath $Private:_folder -PathType Container))
	{
		Try { $null = New-Item -Path $Private:_folder -ItemType Directory -Force -ErrorAction Stop }
		# SILENT-OK: best-effort folder creation, deliberately NOT routed through Write-MyCatchAudit -
		# see this function's own .DESCRIPTION for the full reasoning (every caller already handles a
		# still-missing folder correctly on its own; nothing is lost by staying silent here).
		Catch { $null = $_ }
	}
	Join-Path -Path $Private:_folder -ChildPath 'CatchAudit.jsonl'
}
