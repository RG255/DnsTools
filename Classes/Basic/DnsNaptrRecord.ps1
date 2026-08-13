class DnsNaptrRecord {
	[uint16]$Order            # Order of processing
	[uint16]$Preference       # Preference within same order
	[string]$Flags            # Flags (e.g., "S", "A", "U", "P")
	[string]$Services         # Available services
	[string]$Regexp           # Regular expression for rewriting
	[string]$Replacement      # Replacement domain name

	DnsNaptrRecord(
		[uint16]$ord,
		[uint16]$preference,
		[string]$flags,
		[string]$services,
		[string]$regexp,
		[string]$replacement
	)
	{
		$this.Order = $ord
		$this.Preference = $preference
		$this.Flags = $flags
		$this.Services = $services
		$this.Regexp = $regexp
		$this.Replacement = $replacement
	}

	static [string] ReadCharacterString([DnsBinaryReader]$r)
	{
		$len = $r.ReadUInt8()
		if ($len -eq 0) { return '' }
		$bytes = $r.ReadBytes($len)
		return [System.Text.Encoding]::ASCII.GetString($bytes)
	}

	static [DnsNaptrRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$ord = $r.ReadUInt16BE()
		$pref = $r.ReadUInt16BE()
		$flgs = [DnsNaptrRecord]::ReadCharacterString($r)
		$svcs = [DnsNaptrRecord]::ReadCharacterString($r)
		$rgx = [DnsNaptrRecord]::ReadCharacterString($r)
		$repl = $r.ReadName()

		return [DnsNaptrRecord]::new(
			$ord, $pref, $flgs,
			$svcs, $rgx, $repl
		)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Order)
		$w.WriteUInt16BE($this.Preference)

		# Write flags as character string
		$flagsBytes = [System.Text.Encoding]::ASCII.GetBytes($this.Flags)
		$w.WriteUInt8([byte]$flagsBytes.Length)
		$w.WriteBytes($flagsBytes)

		# Write services as character string
		$servicesBytes = [System.Text.Encoding]::ASCII.GetBytes($this.Services)
		$w.WriteUInt8([byte]$servicesBytes.Length)
		$w.WriteBytes($servicesBytes)

		# Write regexp as character string
		$regexpBytes = [System.Text.Encoding]::ASCII.GetBytes($this.Regexp)
		$w.WriteUInt8([byte]$regexpBytes.Length)
		$w.WriteBytes($regexpBytes)

		# Write replacement domain name
		$w.WriteName($this.Replacement)

		return $w.ToArray()
	}
}
