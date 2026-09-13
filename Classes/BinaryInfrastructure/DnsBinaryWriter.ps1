class DnsBinaryWriter {
	[System.Collections.Generic.List[byte]] $Buffer

	DnsBinaryWriter()
	{$this.Buffer = [System.Collections.Generic.List[byte]]::new()}

	[void]WriteByte([byte]$b)
	{$this.Buffer.Add($b)}

	[void]WriteBytes([byte[]]$bytes)
	{$this.Buffer.AddRange($bytes)}

	[void]WriteUInt8([byte]$value)
	{$this.Buffer.Add($value)}

	[void]WriteUInt16BE([uint16]$value)
	{
		$bytes = [BitConverter]::GetBytes($value)
		if ([BitConverter]::IsLittleEndian)
		{[Array]::Reverse($bytes)}
		$this.Buffer.AddRange($bytes)
	}

	[void]WriteUInt32BE([uint32]$value)
	{
		$bytes = [BitConverter]::GetBytes($value)
		if ([BitConverter]::IsLittleEndian)
		{[Array]::Reverse($bytes)}
		$this.Buffer.AddRange($bytes)
	}

	[void]WriteName([string]$name)
	{
		if ([string]::IsNullOrWhiteSpace($name))
		{
			$this.Buffer.Add(0)
			return
		}

		$labels = $name.TrimEnd('.').Split('.')
		foreach ($label in $labels)
		{
			$lower = ($label -as [string]).ToLowerInvariant()
			$bytes = [System.Text.Encoding]::ASCII.GetBytes($lower)
			$this.Buffer.Add([byte]$bytes.Length)
			$this.Buffer.AddRange($bytes)
		}

		$this.Buffer.Add(0)
	}

	[void]WriteOptRecord([switch]$DoBit)
	{
		$this.WriteByte(0x00)
		$this.WriteUInt16BE(41)
		$this.WriteUInt16BE(4096)
		$this.WriteByte(0x00)
		$this.WriteByte(0x00)
		$flags = if ($DoBit)
		{0x8000}
		else
		{0x0000}
		$this.WriteUInt16BE([uint16]$flags)
		$this.WriteUInt16BE(0)
	}

	[byte[]] ToArray()
	{return $this.Buffer.ToArray()}
}
