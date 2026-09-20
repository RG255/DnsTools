# VENDORED from CommonScripts\0.2\Functions\Disable-MyFunctionTrace.ps1 by Sync-SharedUtilities [SHA256 0CF44B7E704F52052AB13DBDAF9039E8B356406DA2AC4090043261A783B5150D] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Disable-MyFunctionTrace
{
	<#
		.SYNOPSIS
		Turns OFF function-call tracing for this process (the default).

		.DESCRIPTION
		2026-09-15. Clears $env:MyFunctionTraceEnabled. Every instrumented function's external
		If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace } guard then skips
		the call entirely (no function-call overhead, not just a no-op write) - see
		Write-MyFunctionTrace's own doc for why that guard is external rather than a self-check inside
		the writer, and Enable-MyFunctionTrace's own doc for why the env var is a bitmask (2026-09-16).

		Does not clear $env:MyFunctionTraceFilter or $env:MyFunctionTraceSessionId - those are harmless
		to leave set while tracing is off, and clearing them here would lose a session id you may want to
		reuse when you next Enable-MyFunctionTrace.

		.EXAMPLE
		Disable-MyFunctionTrace
	#>
	[CmdletBinding()]
	Param ()
	$env:MyFunctionTraceEnabled = $null
	Write-Output -InputObject 'Function-call tracing is OFF for this process (the default).'
}
