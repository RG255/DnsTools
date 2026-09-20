# VENDORED from CommonScripts\0.2\Functions\Format-MyFunctionTraceLine.ps1 by Sync-SharedUtilities [SHA256 86F39E325F3DC6A93D18CA3A7D9128004D3D7F9FBEEB7C07BB22D9824679DA2B] - DO NOT EDIT (edit the master; Deploy-Modules re-syncs).
Function Format-MyFunctionTraceLine
{
	<#
		.SYNOPSIS
		Internal: builds one fixed-width function-trace log line from a call stack, optionally tagged as
		an error line.

		.DESCRIPTION
		2026-09-15. Shared by Write-MyFunctionTrace (plain call-entry lines) and Get-MyError's
		trace-mirroring addition (error lines) so both produce IDENTICAL field extraction/formatting - the
		exact problem this whole facility was built to fix in the two prior, independent, subtly-different-
		and-both-buggy implementations (Write-MyLog's old -CallStack parameter and DnsTools' own retired
		Write-Trace.ps1, both string-split a Location property instead of using ScriptLineNumber, and
		neither carried Pid/User at all).

		Field mapping, relative to the CALLER of Format-MyFunctionTraceLine (i.e. $CallStack is the caller's
		own Get-PSCallStack() capture, so $CallStack[0] is the caller itself):
			Function:/Line:             $CallStack[0].FunctionName / .ScriptLineNumber (the line INSIDE
			                             the caller where it captured/reported the call stack).
			Called from:/Line:          $CallStack[1].FunctionName / .ScriptLineNumber, or the literal
			                             '<ScriptBlock>' with Line:[0] when $CallStack[1] does not exist
			                             at all (genuinely no caller frame - matches Get-PSCallStack's own
			                             natural output). When $CallStack[1] DOES exist but is itself a
			                             top-level script scope (not inside any function), PowerShell
			                             reports its own FunctionName as the bare literal '<ScriptBlock>'
			                             too - on its own this is useless the moment more than one script
			                             is in play (confirmed live 2026-09-15: a real trace log full of
			                             '<ScriptBlock> Line:[301]' entries with no way to tell which
			                             script), so that specific case is expanded to
			                             '<ScriptBlock:LeafFileName.ps1>' using that frame's own
			                             .ScriptName, which IS available even though .FunctionName is not.
			Module:[Name]               Derived from $CallStack[0].ScriptName's own path (every function's
			                             defining file lives under Modules\<Name>\<Version>\...) - NOT
			                             guessed from the function name, so a vendored function's copy is
			                             correctly attributed to whichever module's copy actually ran.
			Session:[...]               Included only when $env:MyFunctionTraceSessionId is set (see
			                             Enable-MyFunctionTrace's own doc) - lets one logical operation
			                             that spans a NamedPipe client+elevated-server process pair be
			                             filtered out of the shared log as one ordered sequence.

		.PARAMETER CallStack
		The result of Get-PSCallStack(), captured by the IMMEDIATE caller of this function (so
		$CallStack[0] is that caller's own frame, not this function's).

		.PARAMETER ErrorTag
		Optional. When supplied (e.g. an exception type name), the line is built as an ERROR line -
		'Called from:'/'Line:' are replaced with 'ERROR:[ErrorTag] ErrorMessage' - instead of a plain
		call-entry line. Pass together with -ErrorMessage.

		.PARAMETER ErrorMessage
		The error message text to include when -ErrorTag is supplied.

		.OUTPUTS
		[String] one formatted line, no trailing newline.
	#>
	[CmdletBinding(PositionalBinding = $False)]
	[OutputType([String])]
	Param (
		[Parameter(Mandatory)]
		[System.Management.Automation.CallStackFrame[]]$CallStack,
		[String]$ErrorTag     = '',
		[String]$ErrorMessage = ''
	)

	$Private:_current = $CallStack[0]
	$Private:_caller  = If ($CallStack.Count -ge 2) { $CallStack[1] } Else { $null }

	$Private:_callerName = If (-not $Private:_caller) { '<ScriptBlock>' }
	ElseIf ($Private:_caller.FunctionName -eq '<ScriptBlock>' -and $Private:_caller.ScriptName)
	{ '<ScriptBlock:{0}>' -f (Split-Path -Path $Private:_caller.ScriptName -Leaf) }
	Else { $Private:_caller.FunctionName }
	$Private:_callerLine = If ($Private:_caller) { $Private:_caller.ScriptLineNumber } Else { 0 }

	# Module name from the defining file's own path - e.g. '...\Modules\DnsTools\0.7\Functions\X.ps1'
	# -> 'DnsTools'. Not resolvable (e.g. an ad-hoc console function) -> '<none>', never a thrown error.
	$Private:_module = '<none>'
	If ($Private:_current.ScriptName -and ($Private:_current.ScriptName -match '\\Modules\\([^\\]+)\\'))
	{ $Private:_module = $Matches[1] }

	$Private:_line = '{0} Pid:[{1,5}] User: [{2}] Function:[{3}] Line:[{4,5}]' -f
	(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $PID, [Environment]::UserName,
	$Private:_current.FunctionName, $Private:_current.ScriptLineNumber

	$Private:_line += If ($ErrorTag)
	{ ' ERROR:[{0}] {1}' -f $ErrorTag, $ErrorMessage }
	Else
	{ ' Called from:[{0}] Line:[{1,5}]' -f $Private:_callerName, $Private:_callerLine }

	If ($env:MyFunctionTraceSessionId)
	{ $Private:_line += (' Session:[{0}]' -f $env:MyFunctionTraceSessionId) }

	$Private:_line += (' Module:[{0}]' -f $Private:_module)

	$Private:_line
}
