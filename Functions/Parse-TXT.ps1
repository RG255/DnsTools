function Parse-TXT 
{
	param(
		[byte[]]$rdata,
		$packet,
		[int]$offset
	)

	return [DnsTxtRecord]::Parse($rdata)
}