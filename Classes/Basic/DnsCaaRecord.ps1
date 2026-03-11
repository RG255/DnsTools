class DnsCaaRecord {
	[byte]$Flags        # Flags byte (bit 0 = critical flag)
	[string]$Tag        # Property tag (e.g., "issue", "issuewild", "iodef")
	[string]$Value      # Property value

	DnsCaaRecord([byte]$flags, [string]$tg, [string]$value)
	{
		$this.Flags = $flags
		$this.Tag   = $tg
		$this.Value = $value
	}

	static [DnsCaaRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$endPos   = $startPos + $len

		$flgs    = $r.ReadUInt8()
		$tgLen   = $r.ReadUInt8()
		$tgBytes    = $r.ReadBytes($tgLen)
		$tg      = [System.Text.Encoding]::ASCII.GetString($tgBytes)

		$remaining   = $endPos - $r.Position
		$valueBytes  = $r.ReadBytes($remaining)
		$val    = [System.Text.Encoding]::UTF8.GetString($valueBytes)

		return [DnsCaaRecord]::new($flgs, $tg, $val)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.Flags)

		$tgBytes = [System.Text.Encoding]::ASCII.GetBytes($this.Tag)
		$w.WriteUInt8([byte]$tgBytes.Length)
		$w.WriteBytes($tgBytes)

		$valueBytes = [System.Text.Encoding]::UTF8.GetBytes($this.Value)
		$w.WriteBytes($valueBytes)

		return $w.ToArray()
	}

	[bool] IsCritical()
	{
		return ($this.Flags -band 128) -ne 0
	}
}
