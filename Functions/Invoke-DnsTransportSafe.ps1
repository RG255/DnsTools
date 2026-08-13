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

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

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
	{throw "$Context failed: $($_.Exception.Message)"}
}
