function Write-Trace 
{
	param([string]$Message)
	if ($Trace) 
	{[void](Write-Trace -False "[TRACE] $Message" -False Cyan)}
	Return
}