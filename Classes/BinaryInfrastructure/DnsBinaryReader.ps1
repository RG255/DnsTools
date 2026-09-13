class DnsBinaryReader {
	[byte[]] $Buffer
	[int]    $Position

	DnsBinaryReader([byte[]]$buffer)
	{
		$this.Buffer   = $buffer
		$this.Position = 0
	}

	hidden [void]EnsureAvailable([int]$count)
	{
		if ($this.Position + $count -gt $this.Buffer.Length)
		{throw 'Attempt to read beyond end of DNS packet.'}
	}

	[byte] ReadUInt8()
	{
		$this.EnsureAvailable(1)
		$b = $this.Buffer[$this.Position]
		$this.Position++
		return [byte]$b
	}

	[uint16] ReadUInt16BE()
	{
		$this.EnsureAvailable(2)
		$slice = $this.Buffer[$this.Position..($this.Position+1)]
		$this.Position += 2
		if ([BitConverter]::IsLittleEndian)
		{[Array]::Reverse($slice)}
		return [BitConverter]::ToUInt16($slice, 0)
	}

	[uint32] ReadUInt32BE()
	{
		$this.EnsureAvailable(4)
		$slice = $this.Buffer[$this.Position..($this.Position+3)]
		$this.Position += 4
		if ([BitConverter]::IsLittleEndian)
		{[Array]::Reverse($slice)}
		return [BitConverter]::ToUInt32($slice, 0)
	}

	[uint64] ReadUInt64BE()
	{
		$this.EnsureAvailable(8)
		$slice = $this.Buffer[$this.Position..($this.Position+7)]
		$this.Position += 8
		if ([BitConverter]::IsLittleEndian)
		{[Array]::Reverse($slice)}
		return [BitConverter]::ToUInt64($slice, 0)
	}

	[byte[]] ReadBytes([int]$count)
	{
		$this.EnsureAvailable($count)
		$slice = $this.Buffer[$this.Position..($this.Position + $count - 1)]
		$this.Position += $count
		return $slice
	}

	[string] ReadName()
	{
		$labels = New-Object System.Collections.Generic.List[string]
		$visitedOffsets = New-Object System.Collections.Generic.HashSet[int]

		# We track the current read position separately from $this.Position
		# so that pointer jumps do not overwrite the main reader position.
		$pos = $this.Position

		# Track the final position in the wire format (after compression pointer if any)
		$finalPosition = $null

		while ($true)
		{
			# Detect loops BEFORE reading anything at this offset
			if (-not $visitedOffsets.Add($pos)) {
				throw "DNS name compression loop detected at offset $pos"
			}

			# Ensure we can read at least one byte
			if ($pos -ge $this.Buffer.Length) {
				throw "DNS name read beyond packet bounds at offset $pos"
			}

			$len = $this.Buffer[$pos]

			# End of name
			if ($len -eq 0) {
				$pos++
				# Only update final position if we haven't encountered a pointer yet
				if ($null -eq $finalPosition) {
					$finalPosition = $pos
				}
				break
			}

			# Compression pointer
			if (($len -band 0xC0) -eq 0xC0) {
				# Need two bytes for a pointer
				if ($pos + 1 -ge $this.Buffer.Length) {
					throw "DNS compression pointer truncated at offset $pos"
				}

				$b1 = $this.Buffer[$pos]
				$b2 = $this.Buffer[$pos + 1]

				$pointer = (($b1 -band 0x3F) * 256) + $b2

				if ($pointer -ge $this.Buffer.Length) {
					throw "DNS compression pointer out of bounds: $pointer"
				}

				# Set final position to after the 2-byte pointer (only first time)
				if ($null -eq $finalPosition) {
					$finalPosition = $pos + 2
				}

				# Move pos to the pointer target to continue reading the name
				$pos = $pointer
				continue
			}

			# Normal label
			if ($len -gt 63) {
				throw "Invalid DNS label length $len at offset $pos"
			}

			# Ensure label bytes exist
			if ($pos + 1 + $len -gt $this.Buffer.Length) {
				throw "DNS label overruns packet at offset $pos"
			}

			# Extract label
			$labelBytes = $this.Buffer[($pos + 1)..($pos + $len)]
			$label = [System.Text.Encoding]::ASCII.GetString($labelBytes).ToLowerInvariant()
			$labels.Add($label)

			# Advance past label
			$pos += ($len + 1)
		}

		# Update the main reader position to the final wire format position
		$this.Position = $finalPosition

		return ($labels -join '.')
	}
}
