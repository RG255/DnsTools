function Invoke-DnsTransportSafe 
{
	param(
		[Parameter(Mandatory)]
		[ScriptBlock]$Operation,

		[string]$Context = 'DNS transport'
	)

	try 
	{return & $Operation}
	catch 
	{throw "$Context failed: $($_.Exception.Message)"}
}
