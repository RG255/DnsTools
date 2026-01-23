function Get-DnssecNsec3Hash 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$name,

		[Parameter(Mandatory)]
		[int]$Algorithm,   # only 1 (SHA-1) supported for now

		[Parameter(Mandatory)]
		[int]$Iterations,

		[Parameter(Mandatory)]
		[byte[]]$salt
	)

	if ($Algorithm -ne 1) 
	{throw "Get-DnssecNsec3Hash: Only algorithm 1 (SHA-1) is supported (got $Algorithm)."}

	# Canonicalize owner name: lowercase, FQDN, no trailing dot in wire labels
	$labels = $name.TrimEnd('.').ToLower().Split('.')

	# Convert labels to wire format: <len><label>...<0>
	$nameBytesList = [System.Collections.Generic.List[byte]]::new()
	foreach ($label in $labels) 
	{
		$bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
		[void]$nameBytesList.Add([byte]$bytes.Length)
		[void]$nameBytesList.AddRange($bytes)
	}
	[void]$nameBytesList.Add(0) # root label

	$nameBytes = [byte[]]$nameBytesList.ToArray()

	# Initial hash: H( name | salt )
	$sha1 = [System.Security.Cryptography.SHA1]::Create()
	try 
	{
		$input0 = New-Object -TypeName System.Collections.Generic.List[byte]
		[void]$input0.AddRange($nameBytes)
		[void]$input0.AddRange($salt)
		$hash = $sha1.ComputeHash([byte[]]$input0.ToArray())

		# Iterative hashing: for i in 1..Iterations: H( hash | salt )
		for ($i = 0; $i -lt $Iterations; $i++) 
		{
			$input = New-Object -TypeName System.Collections.Generic.List[byte]
			[void]$input.AddRange($hash)
			[void]$input.AddRange($salt)
			$hash = $sha1.ComputeHash([byte[]]$input.ToArray())
		}
	}
	finally 
	{$sha1.Dispose()}

	return $hash
}