# VENDORED from CommonScripts\0.2\Functions\Write-MyFunctionTrace.ps1 by Sync-SharedUtilities [SHA256 6B2748DBD139D70AC6884959CD86B4B1B27B577D050B57CA0F71DBADBC8D42A9] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Write-MyFunctionTrace
{
	<#
		.SYNOPSIS
		Writes one function-entry line to the shared function-trace log.

		.DESCRIPTION
		2026-09-15. Call as the FIRST statement of any function to be traced, guarded by an external
		If so the function-call overhead is skipped entirely when tracing is off (this can end up in
		dozens/hundreds of call sites, so that guard matters at scale):

			Function Set-Verbosity
			{
				Param (...)
				If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }
				...
			}

		For a function with Begin/Process/End blocks, put it in Begin (traces the invocation once, not
		once per pipeline item):
			begin { If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace } }

		2026-09-16: the guard changed from "-eq '1'" to "1 -band (... -as [Int])" now that
		$env:MyFunctionTraceEnabled is a bitmask (see Enable-MyFunctionTrace's own doc for the full
		rationale - lexicographic string comparison ruled out an ordered level, -band/-bor chosen to match
		$InfoDisplay/RedactPattern.Option's existing bitmask convention). The "-as [Int]" wrapper is
		required, not optional: a bare -band/-bor on the raw string throws a terminating conversion error
		on any non-numeric value, which would crash every one of this guard's several-hundred call sites
		at the first statement of the traced function - "-as [Int]" converts best-effort and returns $null
		(falsy, no exception) instead.

		Do NOT add this to a per-item/stream-processing helper whose whole job is to be invoked once per
		element of a loop/stream so an ENCLOSING function can assemble one overall result (e.g. a
		byte-level binary reader's own read methods, called dozens of times while a single higher-level
		function parses one packet) - trace the enclosing function once; tracing the per-element helper
		too multiplies log volume for no real diagnostic value. A genuinely recursive traced function
		(one that calls itself) is NOT this case and should be traced normally - repeated identical
		Function:/Line: entries are the correct, expected output there.

		Replaces two prior, independent, and both-buggy implementations - retired as part of this change:
		Write-MyLog.ps1's old -CallStack parameter (string-split a Location property instead of using
		ScriptLineNumber, no Pid/User) and DnsTools' own module-local Write-Trace.ps1 (same shape of bug).

		PERMANENT EXCLUSION LIST - never instrument these with a trace stamp, or a call into this facility
		can recurse into itself: Write-MyFunctionTrace (this function), Enable-MyFunctionTrace,
		Disable-MyFunctionTrace, Get-MyFunctionTracePath, Format-MyFunctionTraceLine, and Get-MyError's own
		trace-mirroring code path. Same category as the established "never call Write-MyCatchAudit from
		inside Write-MyCatchAudit's own normal path" rule.

		Toggle: $env:MyFunctionTraceEnabled (Enable-/Disable-MyFunctionTrace) - $env:, not $Script:/
		$Global:, so a value set before Start-PipeSession is inherited by the spawned elevated server
		process too (a $Script:/$Global: variable would not cross that process boundary).

		Optional scoping: $env:MyFunctionTraceFilter, a comma-separated list of function names - when set,
		only those functions are actually written, so tracing can be aimed at one area of interest instead
		of firing on every instrumented call site in the process at once.

		Optional correlation: $env:MyFunctionTraceSessionId - see Enable-MyFunctionTrace's own doc for how
		this crosses a NamedPipe elevation boundary via the pipe's own existing serialization channel.

		A trace-log write failure must never take down the operation it is observing - the actual write
		has its own inner Try/Catch (reported via Write-MyCatchAudit, one-directional only: this function
		may call Write-MyCatchAudit, Write-MyCatchAudit must never call back into this one), and the whole
		function is wrapped in an outermost silent Catch as a final backstop.

		.PARAMETER Detail
		Optional free-text annotation appended to the line as ' Detail:[<text>]'. This function does NO
		redaction and NO caller checking of its own: the caller decides WHETHER detail is wanted (guard the
		call with 2 -band ($env:MyFunctionTraceEnabled -as [Int]), so building the text costs nothing when
		tracing is off) and is responsible for the text being safe to persist in a shared log - only the
		calling function knows what its detail actually contains.

		2026-09-20: an earlier version restricted -Detail to a hardcoded caller allowlist (one entry, a
		NamedPipe function). Removed: this file is vendored byte-identically into every module, so that
		list put one module's function names into every other module's copy, and it was never a security
		boundary (anyone able to edit the code could remove it). This function stays generic and remains
		the single place that writes to the trace log; each module supplies its own detail text.

		.PARAMETER SkipFrames
		Number of additional call-stack frames to skip when working out which function is being traced
		(default 0). A thin wrapper that exists only to forward a message here passes 1 so the log line
		names the wrapper's caller and line, not the wrapper. $env:MyFunctionTraceFilter is applied to that
		same (skipped-to) function. Default 0 is exactly the previous behaviour.

		.EXAMPLE
		If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

		.EXAMPLE
		If (2 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace -Detail ('Request:[{0}]' -f $Private:RedactedText) }
	#>
	[CmdletBinding()]
	Param (
		[String]$Detail = '',
		[ValidateRange(0, 20)]
		[Int]$SkipFrames = 0
	)

	Try
	{
		# Drop frame 0 (this function's own frame) - and any -SkipFrames wrapper frames - before handing
		# off - Format-MyFunctionTraceLine expects index 0 to be ITS caller, i.e. the function actually
		# being traced.
		$Private:_stack = @(Get-PSCallStack)
		$Private:_first = 1 + $SkipFrames
		If ($Private:_stack.Count -le $Private:_first) { return }
		$Private:_traced = $Private:_stack[$Private:_first..($Private:_stack.Count - 1)]

		If ($env:MyFunctionTraceFilter)
		{
			$Private:_allow = @($env:MyFunctionTraceFilter -split ',' | ForEach-Object { $_.Trim() })
			If ($Private:_traced[0].FunctionName -notin $Private:_allow) { return }
		}

		$Private:_line = Format-MyFunctionTraceLine -CallStack $Private:_traced

		If ($Detail)
		{ $Private:_line += (' Detail:[{0}]' -f $Detail) }

		Try { Add-Content -LiteralPath (Get-MyFunctionTracePath) -Value $Private:_line -Encoding utf8 -ErrorAction Stop }
		Catch { Write-MyCatchAudit -Source 'Write-MyFunctionTrace: write to the function-trace log' -ErrorRecord $_ }
	}
	# SILENT-OK: tracing itself must never throw or interrupt the real operation it is observing.
	Catch { $null = $_ }
}
