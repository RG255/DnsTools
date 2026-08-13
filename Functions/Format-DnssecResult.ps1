function Format-DnssecResult
{
	<#
	.SYNOPSIS
		Formats a DNSSEC validation result for display.

	.DESCRIPTION
		Converts a DNSSEC validation result object into a human-readable formatted string.

	.PARAMETER result
		The DNSSEC validation result object to format.
	#>
	param(
		[psobject]$result
	)

	if (-not $result) 
	{return 'No result'}

	$status = if ($result.Valid) 
	{'VALID'}
	else 
	{'BOGUS'}

	$msg = "DNSSEC Status: $status`nReason: $($result.Reason)"

	if ($result.Answer) 
	{
		$msg += "`nAnswers:`n"
		foreach ($a in $result.Answer) 
		{$msg += "  $($a.Name) $($a.Type) $($a.RDataObject)`n"}
	}

	return $msg
}