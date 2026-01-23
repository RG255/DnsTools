function Test-DnssecName 
{
	param(
		[string]$name,
		[int]$type = 1
	)

	$result = Resolve-DnssecName -name $name -type $type
	return $result.Valid
}