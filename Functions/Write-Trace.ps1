function Write-Trace
{
	<#
	.SYNOPSIS
		Writes trace output if tracing is enabled.

	.DESCRIPTION
		Conditionally writes trace messages to the console when the module-level Trace variable is set.
		Can also write to a log file when $Script:FTLogFilPath is set.
		Supports call stack logging via the -CallStack parameter.

	.PARAMETER Message
		The trace message to display.

	.PARAMETER CallStack
		The call stack from Get-PSCallStack. When provided, formats output showing
		the current function, its location, and the calling function.

	.EXAMPLE
		Write-Trace -Message "Starting DNS query"

	.EXAMPLE
		If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }
	#>
	param(
		[string]$Message,
		[System.Management.Automation.CallStackFrame[]]$CallStack
	)

	# Build the trace message
	$traceMessage = $null

	if ($CallStack -and $CallStack.Count -ge 1)
	{
		$myDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
		$currentFunc = $CallStack[0].FunctionName
		$currentLocation = if ($CallStack[0].ScriptName) { Split-Path -Leaf $CallStack[0].ScriptName } else { '<console>' }

		if ($CallStack.Count -ge 2)
		{
			$callerFunc = $CallStack[1].FunctionName
			$callerLocation = $CallStack[1].Location
			$traceMessage = '{0} Function:[{1}] in:[{2}] Called from:[{3}] Function:[{4}]' -f $myDate, $currentFunc, $currentLocation, $callerLocation, $callerFunc
		}
		else
		{
			$traceMessage = '{0} Function:[{1}] in:[{2}]' -f $myDate, $currentFunc, $currentLocation
		}
	}
	elseif ($Message)
	{
		$traceMessage = "[TRACE] $Message"
	}

	if (-not $traceMessage) { return }

	# Write to console if Trace is enabled
	$traceEnabled = Get-Variable -Name Trace -Scope Script -ValueOnly -ErrorAction SilentlyContinue
	if ($traceEnabled)
	{
		Write-Host $traceMessage -ForegroundColor Cyan
	}

	# Write to log file if FTLogFilPath is set (does NOT check $FTrace to avoid loops)
	$logPath = Get-Variable -Name FTLogFilPath -Scope Script -ValueOnly -ErrorAction SilentlyContinue
	if ($logPath)
	{
		try
		{
			Add-Content -Path $logPath -Value $traceMessage -ErrorAction Stop
		}
		catch
		{
			# Silently fail to avoid disrupting the main operation
		}
	}
}