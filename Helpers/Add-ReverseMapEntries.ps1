[CmdletBinding()]
param(
	[Parameter(Mandatory)]
	[HashTable] $Map
)

# Validate input
if (-not ($Map -is [System.Collections.IDictionary]))
{throw 'Input must be a hashtable or ordered hashtable.'}

# Detect ordered vs unordered
$isOrdered = $Map -is [System.Collections.Specialized.OrderedDictionary]

# Copy keys so we don't modify while iterating
$keys = @($Map.Keys)

foreach ($key in $keys)
{
	$value = $Map[$key]

	# Skip null values (but not 0 or empty string which are valid)
	if ($null -eq $value)
	{continue}

	# Skip if reverse entry already exists
	if ($Map.Contains($value))
	{continue}

	if ($isOrdered)
	{
		# OrderedDictionary requires .Add()
		$Map.Add($value, $key)
	}
	else
	{
		# Normal hashtable supports simple assignment
		$Map[$value] = $key
	}
}

return $Map