class DnsTxtRecord {
	[string[]]$Strings

	DnsTxtRecord([string[]]$strings) 
	{$this.Strings = $strings}

	static [DnsTxtRecord] Parse([byte[]]$rdata) 
	{
		$r          = [DnsBinaryReader]::new($rdata)
		$stringsval = New-Object -TypeName System.Collections.Generic.List[string]

		while ($r.Position -lt $r.Buffer.Length) 
		{
			$lenval   = $r.ReadUInt8()
			$bytesval = $r.ReadBytes($lenval)
			$null     = $stringsval.Add([System.Text.Encoding]::ASCII.GetString($bytesval))
		}

		return [DnsTxtRecord]::new($stringsval.ToArray())
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