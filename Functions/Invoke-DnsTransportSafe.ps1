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

	try 
	{return & $Operation}
	catch 
	{throw "$Context failed: $($_.Exception.Message)"}
}
