# VENDORED from CommonScripts\0.2\Functions\Enable-MyFunctionTrace.ps1 by Sync-SharedUtilities [SHA256 2A3ABF9350CD8B71C36B150D22CAE9EEC7C63969DDEF9FFFE770674106B941D0] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Enable-MyFunctionTrace
{
	<#
		.SYNOPSIS
		Turns ON function-call tracing for this process (and, for a NamedPipe-elevated operation, the
		spawned elevated server process too).

		.DESCRIPTION
		2026-09-15. Sets $env:MyFunctionTraceEnabled to the bitmask you pass in -Option (mandatory, 1-3 -
see .PARAMETER Option; it used to default to 1). Every instrumented
		function's If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace } guard
		then starts writing to the shared log (see Get-MyFunctionTracePath) -
		$env:ProgramData\FunctionTrace\FunctionTrace.log.

		2026-09-16: $env:MyFunctionTraceEnabled changed from a bare '1'/unset flag to a BITMASK, via the
		new -Option parameter below, so the env var can carry more than one independent signal without a
		repo-wide guard rewrite each time a new one is needed. A bitmask (not an ordered level like '2'
		meaning "more than 1") was chosen deliberately: PowerShell's -gt/-ge on two STRINGS (which is what
		every $env: var always is) does a lexicographic, not numeric, comparison - '10' -gt '9' is $False,
		since '1' sorts before '9' character-by-character - a silent bug the moment a level reaches double
		digits. -band/-bor coerce both operands to integer regardless of string origin, sidestepping that
		trap entirely, and this matches two conventions this codebase already uses for exactly this kind
		of "which of several independent behaviours do you want" question: NamedPipe's own $InfoDisplay
		(0/1/2/4/8, OR-able) and RedactPattern.Option (1/2/4).
		  Bit 1 = ordinary per-function entry tracing (this function's default, unchanged meaning from
		          before this change).
		  Bit 2 = curated "action" detail: callers that choose to (NamedPipe's Get-SBResult for each pipe
		          request it runs, and any consuming module for its own operation steps) pass a short
		          Detail:[...] text to Write-MyFunctionTrace's -Detail parameter - see that function's own
		          doc comment. Without bit 1 this gives just the meaningful steps, none of the plumbing.
		  Bit 4+ reserved, undesigned - extend by adding a new bit here, not by inventing a second env var.
		Every guard site must use "-as [Int]" (not a bare [Int] cast, not raw -band/-bor on the string
		directly) - confirmed empirically that a non-numeric env var value (a stray typo, e.g. 'garbage')
		makes a raw -band/-bor THROW a terminating System.Int32 conversion error at the guard itself,
		before the traced function's own body or Try block even starts - worse than the old -eq '1' guard,
		which never throws (any non-'1' string is just "off"). "-as [Int]" converts on a best-effort basis
		and returns $null (falsy, no exception) instead of throwing on bad input, and $null/absent/empty
		string all confirmed falsy under -band/-bor with no exception either.

		$env:, not $Script:/$Global:, is deliberate: a NamedPipe elevated server is a SEPARATE process
		from its GUI/CLI caller, spawned via Start-Process. Environment variables ARE inherited by a
		normally-spawned child process, so calling this before Start-PipeSession means the elevated side
		also traces - a real fix over the retired $Script:FTrace design, which could never reach an
		elevated server without editing that module's own DefineVariables defaults.

		CAVEAT, found and fixed 2026-09-16: the above is true for a normal (same-privilege) spawn, but
		NOT across a -Verb RunAs elevation boundary - that goes through a separate broker process
		(consent.exe/AppInfo) which gives the new process a FRESH environment, not inherited from the
		caller. A genuinely UAC-elevated NamedPipe server (e.g. Macrium's Open-MyElevatedSession with
		AdminRequired=$true, from a non-admin caller) silently produced ZERO trace output even with this
		function called first - confirmed live. Start-PipeSession.ps1 now also stamps
		$env:MyFunctionTraceEnabled/$env:MyFunctionTraceSessionId onto ServerClientParams (which already
		crosses this exact boundary via ConvertTo-Serial/-SerialData regardless of elevation), and
		Start-PipeServerOrClient.ps1's spawn bootstrap restores both from there before the consumer
		module even loads - so tracing now reaches the elevated side either way, not just the
		same-privilege case this function's own inheritance claim was only ever true for.

		Related toggles (not set by this function):
		- $env:MyFunctionTraceFilter - comma-separated function names; when set, only those are written.
		- $env:MyFunctionTraceSessionId - correlates one logical operation across BOTH processes of a
		  NamedPipe session (which otherwise have different Pids and so cannot be told apart by Pid
		  alone), and (2026-09-20) names this window's trace file. This function now creates one
		  automatically (8 hex chars from a GUID, same pattern Write-MyCatchAudit uses for its own
		  per-entry Id) when none is set; you can still set your own before calling it. Set BEFORE opening
		  the pipe session - Start-PipeSession.ps1 picks it up automatically (see the CAVEAT above), no
		  separate options field needed.

		Process-scoped on purpose, same reasoning as Enable-MyCatchAudit: a GUI/CLI client and any
		elevated server it talks to are separate processes, so this call in one does not silently also
		affect some unrelated process.

		.PARAMETER Option
		REQUIRED (2026-09-20: no default any more - say which bits you want). Bitmask written to
		$env:MyFunctionTraceEnabled, 1 to 3:
		  1 = ordinary per-function call tracing (the full, noisy call flow)
		  2 = curated action detail only (the meaningful steps, no plumbing)
		  3 = both
		Use Disable-MyFunctionTrace to turn tracing off (0 is not accepted here). The value is echoed
		back in the one confirmation line as Option=N, which is what was enabled.

		ValidateRange caps this at 3 (1+2), the highest combination of CURRENTLY DEFINED bits - matches
		the same convention NamedPipe's own $InfoDisplay parameter already uses (its range caps at 15,
		the sum of its own currently-defined bits, not open-ended). This is a deliberate maintenance
		cost, not an oversight: the next bit added to this facility (bit 4+, see this function's own
		.DESCRIPTION) must widen this range as part of that same change, or -Option would silently
		reject the very value that change is meant to enable.

		.PARAMETER NewSession
		Start a fresh trace file for this window even if a session id is already set. Each Enable call
		otherwise reuses the window's existing $env:MyFunctionTraceSessionId, so re-enabling keeps
		appending to the same file. With no id set, one is created automatically.

		The session id names the log file (Get-MyFunctionTracePath returns FunctionTrace-Session-<Id>.log),
		so two PowerShell windows tracing at once no longer interleave in one file. It also crosses to a
		NamedPipe elevated server (see the CAVEAT above), so a client and its own server share one file.
		Call this BEFORE Start-PipeSession.

		.EXAMPLE
		Enable-MyFunctionTrace -Option 1
		# ... reproduce the flow you want to see ...
		Disable-MyFunctionTrace

		.EXAMPLE
		Enable-MyFunctionTrace -Option 3
		# ordinary tracing AND the curated action detail (Get-SBResult request text, plus any consumer's own steps)
		Disable-MyFunctionTrace
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory, HelpMessage = 'Bitmask: 1=ordinary tracing, 2=curated action detail, 3=both')]
		[ValidateRange(1, 3)]
		[Int]$Option,
		[Switch]$NewSession
	)
	# Set the session id FIRST: Get-MyFunctionTracePath derives the log file name from it.
	If ($NewSession -or -not $env:MyFunctionTraceSessionId)
	{ $env:MyFunctionTraceSessionId = [Guid]::NewGuid().ToString('N').Substring(0, 8) }
	$env:MyFunctionTraceEnabled = $Option.ToString()
	$Private:LogPath = Get-MyFunctionTracePath

	# Create the file HERE, in the caller's own process, rather than leaving it to whichever process
	# happens to log first. A NamedPipe elevated server runs as a different account (an admin); if IT
	# creates the per-session file, the non-elevated client is denied write access to it and every one
	# of the client's trace lines is lost (found 2026-09-20 with a consuming module: 6 UnauthorizedAccess catch
	# audits). The reverse is fine - an elevated admin can append to a file its client created.
	Try
	{
		If (-not (Test-Path -LiteralPath $Private:LogPath))
		{ $null = New-Item -Path $Private:LogPath -ItemType File -ErrorAction Stop }
	}
	Catch { Write-MyCatchAudit -Source 'Enable-MyFunctionTrace: pre-creating the trace log file' -ErrorRecord $_ }

	Write-Output -InputObject ('Function-call tracing is ON (Option={0}) for this process. Log: {1}' -f $Option, $Private:LogPath)
}
