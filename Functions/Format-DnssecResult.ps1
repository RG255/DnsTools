function Format-DnssecResult 
{
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