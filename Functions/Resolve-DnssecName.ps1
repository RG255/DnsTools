function Resolve-DnssecName 
{
	param(
		[string]$name,
		[int]$type = 1
	)

	return Resolve-Dnssec -name $name -type $type
}