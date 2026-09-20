function Invoke-DnsTransportSafe
{
	<#
	.SYNOPSIS
		Executes a DNS transport operation with enhanced error handling.

	.DESCRIPTION
		Wraps a DNS transport operation to provide consistent error handling and context.

	.PARAMETER Operation
		The script block containing the DNS operation to execute.

	.PARAMETER Context
		The context string to include in error messages (default: 'DNS transport').
	#>
	param(
		[Parameter(Mandatory)]
		[ScriptBlock]$Operation,

		[string]$Context = 'DNS transport'
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	# EAP=Stop is what makes the catch below actually work. Without it this wrapper caught only
	# TERMINATING errors, so a cmdlet failing NON-terminatingly inside $Operation slipped past
	# and the wrapper returned as though the transport had succeeded - the caller got a partial
	# or empty result and no indication anything went wrong.
	#
	# Measured 2026-08-13 by exercising the shipped function:
	#   throw inside $Operation                     -> caught          (the case it was written for)
	#   NON-terminating error inside $Operation     -> NOT caught, returned 'transport-result'
	#   UNSUPPRESSED Get-Item on a missing path     -> NOT caught, error printed, returned normally
	# With this line, the last two are caught. Verified in the same run that an explicit
	# -ErrorAction SilentlyContinue inside $Operation is STILL honoured, so deliberate
	# suppression keeps working and this does not manufacture false failures (anti-pattern 3,
	# the trap that fixing anti-pattern 1 usually creates).
	$ErrorActionPreference = 'Stop'

	try
	{return & $Operation}
	catch
	{
		# 2026-09-15: also runs Get-MyError here - this module's first real caller of it. Purely
		# additive: -PreserveErrors so $Global:Error is untouched for whatever caller catches the
		# re-thrown exception next, and the return value is discarded ($null =) since the re-thrown
		# message text below is unchanged - the point is Get-MyError's own automatic inline
		# function-trace mirroring (see its own .NOTES), which needs a real call site to ever fire
		# for this module, not a behavior change here.
		$null = Get-MyError -PreserveErrors
		throw "$Context failed: $($_.Exception.Message)"
	}
}
