function Get-DnssecCanonicalNameWire 
{
	param([string]$name)

	$labels = $name.TrimEnd('.').ToLower().Split('.')

	# Force a strongly typed List[byte]
	$bytes = New-Object -TypeName 'System.Collections.Generic.List[byte]'

	foreach ($label in $labels) 
	{
		$labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)

		# Explicit cast ensures Add() receives a byte
		$bytes.Add([byte]$labelBytes.Length)

		# Explicit cast ensures AddRange() receives IEnumerable[byte]
		$bytes.AddRange([byte[]]$labelBytes)
	}

	# Root label
	$bytes.Add([byte]0)

	# Force return type to byte[]
	return [byte[]]$bytes.ToArray()
}