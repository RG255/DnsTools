class DnsTxtRecord {
	[string[]]$Strings

	DnsTxtRecord([string[]]$strings) 
	{$this.Strings = $strings}

	static [DnsTxtRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos   = $r.Position
		$endPos     = $startPos + $len
		$strs = New-Object -TypeName System.Collections.Generic.List[string]

		while ($r.Position -lt $endPos)
		{
			$len   = $r.ReadUInt8()
			$bytes = $r.ReadBytes($len)
			$null     = $strs.Add([System.Text.Encoding]::ASCII.GetString($bytes))
		}

		return [DnsTxtRecord]::new($strs.ToArray())
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		foreach ($s in $this.Strings) 
		{
			$bytes = [System.Text.Encoding]::ASCII.GetBytes($s)
			$w.WriteUInt8([byte]$bytes.Length)
			$w.WriteBytes($bytes)
		}
		return $w.ToArray()
	}
}