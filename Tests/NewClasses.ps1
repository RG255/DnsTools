# ============================================================
#region 1. Binary Infrastructure (lowest-level dependencies)
# ============================================================

class DnsBinaryWriter {
	[System.Collections.Generic.List[byte]] $Buffer

	DnsBinaryWriter() {
		$this.Buffer = [System.Collections.Generic.List[byte]]::new()
	}

	[void]WriteByte([byte]$b) {
		$this.Buffer.Add($b)
	}

	[void]WriteBytes([byte[]]$bytes) {
		$this.Buffer.AddRange($bytes)
	}

	[void]WriteUInt8([byte]$value) {
		$this.Buffer.Add($value)
	}

	[void]WriteUInt16BE([uint16]$value) {
		$bytes = [BitConverter]::GetBytes($value)
		if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
		$this.Buffer.AddRange($bytes)
	}

	[void]WriteUInt32BE([uint32]$value) {
		$bytes = [BitConverter]::GetBytes($value)
		if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
		$this.Buffer.AddRange($bytes)
	}

	[void]WriteName([string]$name) {
		if ([string]::IsNullOrWhiteSpace($name)) {
			$this.Buffer.Add(0)
			return
		}

		$labels = $name.TrimEnd('.').Split('.')
		foreach ($label in $labels) {
			$bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
			$this.Buffer.Add([byte]$bytes.Length)
			$this.Buffer.AddRange($bytes)
		}

		$this.Buffer.Add(0)
	}

	[void]WriteOptRecord([switch]$DoBit) {
		$this.WriteByte(0x00)
		$this.WriteUInt16BE(41)
		$this.WriteUInt16BE(4096)
		$this.WriteByte(0x00)
		$this.WriteByte(0x00)
		$flags = if ($DoBit) { 0x8000 } else { 0x0000 }
		$this.WriteUInt16BE([uint16]$flags)
		$this.WriteUInt16BE(0)
	}

	[byte[]] ToArray() {
		return $this.Buffer.ToArray()
	}
}

class DnsBinaryReader {
	[byte[]] $Buffer
	[int]    $Position

	DnsBinaryReader([byte[]]$buffer) {
		$this.Buffer   = $buffer
		$this.Position = 0
	}

	hidden [void]EnsureAvailable([int]$count) {
		if ($this.Position + $count -gt $this.Buffer.Length) {
			throw 'Attempt to read beyond end of DNS packet.'
		}
	}

	[byte] ReadUInt8() {
		$this.EnsureAvailable(1)
		$b = $this.Buffer[$this.Position]
		$this.Position++
		return [byte]$b
	}

	[uint16] ReadUInt16BE() {
		$this.EnsureAvailable(2)
		$slice = $this.Buffer[$this.Position..($this.Position+1)]
		$this.Position += 2
		if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($slice) }
		return [BitConverter]::ToUInt16($slice, 0)
	}

	[uint32] ReadUInt32BE() {
		$this.EnsureAvailable(4)
		$slice = $this.Buffer[$this.Position..($this.Position+3)]
		$this.Position += 4
		if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($slice) }
		return [BitConverter]::ToUInt32($slice, 0)
	}

	[uint64] ReadUInt64BE() {
		$this.EnsureAvailable(8)
		$slice = $this.Buffer[$this.Position..($this.Position+7)]
		$this.Position += 8
		if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($slice) }
		return [BitConverter]::ToUInt64($slice, 0)
	}

	[byte[]] ReadBytes([int]$count) {
		$this.EnsureAvailable($count)
		$slice = $this.Buffer[$this.Position..($this.Position + $count - 1)]
		$this.Position += $count
		return $slice
	}

	[string] ReadName() {
		$labels         = New-Object -TypeName System.Collections.Generic.List[string]
		$visitedOffsets = New-Object -TypeName System.Collections.Generic.HashSet[int]

		while ($true) {
			$this.EnsureAvailable(1)
			$len = $this.Buffer[$this.Position]

			if (($len -band 0xC0) -eq 0xC0) {
				$this.EnsureAvailable(2)
				$b1 = $this.Buffer[$this.Position]
				$b2 = $this.Buffer[$this.Position+1]
				$this.Position += 2

				$pointer = (($b1 -band 0x3F) * 256) + $b2

				if ($pointer -ge $this.Buffer.Length) { throw 'DNS compression pointer out of bounds' }
				if ($visitedOffsets.Contains($pointer)) { throw 'DNS name compression loop detected.' }

				$visitedOffsets.Add($pointer)
				if ($visitedOffsets.Count -gt 10) { throw 'Excessive DNS compression pointers' }

				$saved = $this.Position
				$this.Position = $pointer
				$labels.AddRange($this.ReadName().Split('.'))
				$this.Position = $saved
				break
			}

			if ($len -eq 0) {
				$this.Position++
				break
			}

			$this.EnsureAvailable($len + 1)
			$this.Position++
			$labelBytes = $this.Buffer[$this.Position..($this.Position + $len - 1)]
			$this.Position += $len
			$labels.Add([System.Text.Encoding]::ASCII.GetString($labelBytes))
		}

		return ($labels -join '.')
	}
}

#endregion
# ============================================================



# ============================================================
#region 2. Core DNS Structures (Header + Question)
# ============================================================

class DnsHeader {
	[uint16]$Id
	[uint16]$Flags
	[uint16]$QdCount
	[uint16]$AnCount
	[uint16]$NsCount
	[uint16]$ArCount

	DnsHeader([uint16]$id, [uint16]$flags, [uint16]$qd, [uint16]$an, [uint16]$ns, [uint16]$ar) {
		$this.Id      = $id
		$this.Flags   = $flags
		$this.QdCount = $qd
		$this.AnCount = $an
		$this.NsCount = $ns
		$this.ArCount = $ar
	}

	static [DnsHeader] Parse([DnsBinaryReader]$r) {
		$idValue      = $r.ReadUInt16BE()
		$flagsValue   = $r.ReadUInt16BE()
		$qdValue      = $r.ReadUInt16BE()
		$anValue      = $r.ReadUInt16BE()
		$nsValue      = $r.ReadUInt16BE()
		$arValue      = $r.ReadUInt16BE()
		return [DnsHeader]::new($idValue, $flagsValue, $qdValue, $anValue, $nsValue, $arValue)
	}

	[void]Write([DnsBinaryWriter]$w) {
		$w.WriteUInt16BE($this.Id)
		$w.WriteUInt16BE($this.Flags)
		$w.WriteUInt16BE($this.QdCount)
		$w.WriteUInt16BE($this.AnCount)
		$w.WriteUInt16BE($this.NsCount)
		$w.WriteUInt16BE($this.ArCount)
	}
}

class DnsQuestion {
	[string]$Name
	[uint16]$Type
	[uint16]$Class

	DnsQuestion([string]$name, [uint16]$type, [uint16]$class) {
		$this.Name  = $name
		$this.Type  = $type
		$this.Class = $class
	}

	static [DnsQuestion] Parse([DnsBinaryReader]$r) {
		$nameValue  = $r.ReadName()
		$typeValue  = $r.ReadUInt16BE()
		$classValue = $r.ReadUInt16BE()
		return [DnsQuestion]::new($nameValue, $typeValue, $classValue)
	}

	[void]Write([DnsBinaryWriter]$w) {
		$w.WriteName($this.Name)
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
	}
}

#endregion
# ============================================================



# ============================================================
#region 3. Basic RDATA Types (simple, self-contained)
# ============================================================

class DnsARecord {
	[string]$Address
	static [DnsARecord] Parse([byte[]]$rdata) {
		return [DnsARecord]@{
			Address = ([System.Net.IPAddress]::new($rdata)).ToString()
		}
	}
}

class DnsAaaaRecord {
	[string]$Address
	static [DnsAaaaRecord] Parse([byte[]]$rdata) {
		return [DnsAaaaRecord]@{
			Address = ([System.Net.IPAddress]::new($rdata)).ToString()
		}
	}
}

class DnsCnameRecord {
	[string]$Target

	DnsCnameRecord([string]$target) {
		$this.Target = $target
	}

	static [DnsCnameRecord] Parse([byte[]]$rdata) {
		$r = [DnsBinaryReader]::new($rdata)
		return [DnsCnameRecord]::new($r.ReadName())
	}

	[byte[]]ToWire() {
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.Target)
		return $w.ToArray()
	}
}

class DnsMxRecord {
	[uint16]$Preference
	[string]$Exchange

	DnsMxRecord([uint16]$pref, [string]$exch) {
		$this.Preference = $pref
		$this.Exchange   = $exch
	}

	static [DnsMxRecord] Parse([byte[]]$rdata) {
		$r       = [DnsBinaryReader]::new($rdata)
		$prefval = $r.ReadUInt16BE()
		$exchval = $r.ReadName()
		return [DnsMxRecord]::new($prefval, $exchval)
	}

	[byte[]]ToWire() {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Preference)
		$w.WriteName($this.Exchange)
		return $w.ToArray()
	}
}

class DnsTxtRecord {
	[string[]]$Strings

	DnsTxtRecord([string[]]$strings) {
		$this.Strings = $strings
	}

	static [DnsTxtRecord] Parse([byte[]]$rdata) {
		$r          = [DnsBinaryReader]::new($rdata)
		$stringsval = New-Object -TypeName System.Collections.Generic.List[string]

		while ($r.Position -lt $r.Buffer.Length) {
			$lenval   = $r.ReadUInt8()
			$bytesval = $r.ReadBytes($lenval)
			$null     = $stringsval.Add([System.Text.Encoding]::ASCII.GetString($bytesval))
		}

		return [DnsTxtRecord]::new($stringsval.ToArray())
	}

	[byte[]]ToWire() {
		$w = [DnsBinaryWriter]::new()
		foreach ($s in $this.Strings) {
			$bytes = [System.Text.Encoding]::ASCII.GetBytes($s)
			$w.WriteUInt8([byte]$bytes.Length)
			$w.WriteBytes($bytes)
		}
		return $w.ToArray()
	}
}

class DnsSrvRecord {
	[uint16]$Priority
	[uint16]$Weight
	[uint16]$Port
	[string]$Target

	DnsSrvRecord([uint16]$pri,[uint16]$wgt,[uint16]$port,[string]$target) {
		$this.Priority = $pri
		$this.Weight   = $wgt
		$this.Port     = $port
		$this.Target   = $target
	}

	static [DnsSrvRecord] Parse([byte[]]$rdata) {
		$r       = [DnsBinaryReader]::new($rdata)
		$prival  = $r.ReadUInt16BE()
		$wgtval  = $r.ReadUInt16BE()
		$portval = $r.ReadUInt16BE()
		$tgtval  = $r.ReadName()
		return [DnsSrvRecord]::new($prival,$wgtval,$portval,$tgtval)
	}

	[byte[]]ToWire() {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Priority)
		$w.WriteUInt16BE($this.Weight)
		$w.WriteUInt16BE($this.Port)
		$w.WriteName($this.Target)
		return $w.ToArray()
	}
}

class DnsNsRecord {
	[string] $NsName
	DnsNsRecord([string]$nsName) {
		$this.NsName = $nsName
	}
}

#endregion
# ============================================================



# ============================================================
#region 4. DNSSEC RDATA Types (cryptographic / advanced)
# ============================================================

class DnsDnskeyRecord {
	[uint16]$Flags
	[byte]  $Protocol
	[byte]  $Algorithm
	[byte[]]$PublicKey
	[uint16]$KeyTag
    
	DnsDnskeyRecord([uint16]$flags,[byte]$proto,[byte]$alg,[byte[]]$key) {
		$this.Flags     = $flags
		$this.Protocol  = $proto
		$this.Algorithm = $alg
		$this.PublicKey = $key
		$this.KeyTag = [DnsDnskeyRecord]::ComputeKeyTag($flags, $proto, $alg, $key)
	}
    
	static [DnsDnskeyRecord] Parse([byte[]]$rdata) {
		$r        = [DnsBinaryReader]::new($rdata)
		$flagsval = $r.ReadUInt16BE()
		$protoVal = $r.ReadUInt8()
		$algVal   = $r.ReadUInt8()
		$keyVal   = $r.ReadBytes($rdata.Length - $r.Position)
		return [DnsDnskeyRecord]::new($flagsval, $protoVal, $algVal, $keyVal)
	}

	static [uint16] ComputeKeyTag(
		[uint16]$flags,
		[byte]$proto,
		[byte]$alg,
		[byte[]]$key
	) {
		$sum = 0
		$rdata = New-Object -TypeName System.Collections.Generic.List[byte]

		$flagsBytes = [BitConverter]::GetBytes($flags)
		if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($flagsBytes) }
		$rdata.AddRange($flagsBytes)

		$rdata.Add($proto)
		$rdata.Add($alg)
		$rdata.AddRange($key)

		$i = 0
		foreach ($b in $rdata) {
			if ($i % 2 -eq 0) { $sum += $b * 256 }
			else { $sum += $b }
			$i++
		}

		$sum += ($sum -shl 16) -band 0xFFFF0000
		return [uint16]($sum -band 0xFFFF)
	}
}

class DnsDsRecord {
	[uint16]$KeyTag
	[byte]  $Algorithm
	[byte]  $DigestType
	[byte[]]$Digest

	DnsDsRecord([uint16]$tag,[byte]$alg,[byte]$dtype,[byte[]]$digest) {
		$this.KeyTag     = $tag
		$this.Algorithm  = $alg
		$this.DigestType = $dtype
		$this.Digest     = $digest
	}

	static [DnsDsRecord] Parse([byte[]]$rdata) {
		$r       = [DnsBinaryReader]::new($rdata)
		$tagval  = $r.ReadUInt16BE()
		$algVal  = $r.ReadUInt8()
		$dtypeval = $r.ReadUInt8()
		$digval  = $r.ReadBytes($rdata.Length - $r.Position)
		return [DnsDsRecord]::new($tagval,$algVal,$dtypeval,$digval)
	}

	[byte[]]ToWire() {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.KeyTag)
		$w.WriteUInt8($this.Algorithm)
		$w.WriteUInt8($this.DigestType)
		$w.WriteBytes($this.Digest)
		return $w.ToArray()
	}

	[string] GetDigestHex() {
		return ($this.Digest | ForEach-Object { $_.ToString('x2') }) -join ''
	}
}

class DnsRrsigRecord {
	[uint16]$TypeCovered
	[byte]  $Algorithm
	[byte]  $Labels
	[uint32]$OriginalTtl
	[uint32]$Expiration
	[uint32]$Inception
	[uint16]$KeyTag
	[string]$SignerName
	[byte[]]$Signature

	DnsRrsigRecord(
		[uint16]$typeC,[byte]$alg,[byte]$labels,
		[uint32]$origTtl,[uint32]$exp,[uint32]$inc,
		[uint16]$keyTag,[string]$signer,[byte[]]$sig
	) {
		$this.TypeCovered = $typeC
		$this.Algorithm   = $alg
		$this.Labels      = $labels
		$this.OriginalTtl = $origTtl
		$this.Expiration  = $exp
		$this.Inception   = $inc
		$this.KeyTag      = $keyTag
		$this.SignerName  = $signer
		$this.Signature   = $sig
	}

	static [DnsRrsigRecord] Parse([byte[]]$rdata) {
		$r        = [DnsBinaryReader]::new($rdata)
		$typeCval = $r.ReadUInt16BE()
		$algVal   = $r.ReadUInt8()
		$labelsval = $r.ReadUInt8()
		$origval  = $r.ReadUInt32BE()
		$expval   = $r.ReadUInt32BE()
		$incval   = $r.ReadUInt32BE()
		$tagval   = $r.ReadUInt16BE()
		$signerval = $r.ReadName()
		$sigval   = $r.ReadBytes($rdata.Length - $r.Position)
		return [DnsRrsigRecord]::new(
			$typeCval,$algVal,$labelsval,$origval,$expval,$incval,$tagval,$signerval,$sigval
		)
	}

	[byte[]]ToWireHeaderAndName() {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.TypeCovered)
		$w.WriteUInt8($this.Algorithm)
		$w.WriteUInt8($this.Labels)
		$w.WriteUInt32BE($this.OriginalTtl)
		$w.WriteUInt32BE($this.Expiration)
		$w.WriteUInt32BE($this.Inception)
		$w.WriteUInt16BE($this.KeyTag)
		$w.WriteBytes( [byte[]](Get-DnssecCanonicalNameWire -Name $this.SignerName) )
		return $w.ToArray()
	}
}

class DnsNsecRecord {
	[string] $NextDomainName
	[int[]]  $Types

	DnsNsecRecord([string]$next,[int[]]$types) {
		$this.NextDomainName = $next
		$this.Types          = $types
	}

	static [string] ReadUncompressedName([DnsBinaryReader]$r) {
		$labels = New-Object -TypeName System.Collections.Generic.List[string]

		while ($true) {
			$len = $r.ReadUInt8()
			if ($len -eq 0) { break }

			$labelBytes = $r.ReadBytes($len)
			$labels.Add([System.Text.Encoding]::ASCII.GetString($labelBytes))
		}

		return ($labels -join '.')
	}

	static [DnsNsecRecord] Parse([byte[]]$rdata) {
		$r        = [DnsBinaryReader]::new($rdata)
		$nextval  = [DnsNsecRecord]::ReadUncompressedName($r)
		$typesval = New-Object -TypeName System.Collections.Generic.List[int]

		while ($r.Position -lt $r.Buffer.Length) {
			$blockval = $r.ReadUInt8()
			$lenval   = $r.ReadUInt8()

			if ($lenval -lt 1 -or $lenval -gt 32) {
				throw "Invalid NSEC bitmap length: $lenval"
			}

			$bitsval  = $r.ReadBytes($lenval)

			for ($b = 0; $b -lt $bitsval.Length; $b++) {
				for ($bit = 0; $bit -lt 8; $bit++) {
					if ($bitsval[$b] -band (1 -shl (7-$bit))) {
						$null = $typesval.Add($blockval * 256 + $b*8 + $bit)
					}
				}
			}
		}

		return [DnsNsecRecord]::new($nextval, $typesval.ToArray())
	}

	[byte[]]ToWire() {
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.NextDomainName)

		$byBlock = @{}
		foreach ($t in $this.Types) {
			$block  = [int]([math]::Floor($t / 256))
			$offset = $t % 256
			if (-not $byBlock.ContainsKey($block)) {
				$byBlock[$block] = New-Object -TypeName System.Collections.Generic.List[int]
			}
			$null = $byBlock[$block].Add($offset)
		}

		foreach ($kv in $byBlock.GetEnumerator() | Sort-Object -Property Key) {
			$block   = [byte]$kv.Key
			$offsets = $kv.Value | Sort-Object
			$maxByte = [int]([math]::Floor(($offsets | Measure-Object -Maximum).Maximum / 8))
			$bitmap  = New-Object -TypeName 'byte[]' -ArgumentList ($maxByte+1)

			foreach ($o in $offsets) {
				$b   = [int]([math]::Floor($o / 8))
				$bit = $o % 8
				$bitmap[$b] = $bitmap[$b] -bor (1 -shl (7-$bit))
			}

			$w.WriteUInt8($block)
			$w.WriteUInt8([byte]$bitmap.Length)
			$w.WriteBytes($bitmap)
		}

		return $w.ToArray()
	}
}

class DnsNsec3Record {
	[byte]  $HashAlgorithm
	[byte]  $Flags
	[uint16]$Iterations
	[byte[]]$Salt
	[byte[]]$NextHash
	[int[]] $Types

	DnsNsec3Record(
		[byte]$alg,[byte]$flags,[uint16]$iter,
		[byte[]]$salt,[byte[]]$nextHash,[int[]]$types
	) {
		$this.HashAlgorithm = $alg
		$this.Flags         = $flags
		$this.Iterations    = $iter
		$this.Salt          = $salt
		$this.NextHash      = $nextHash
		$this.Types         = $types
	}

	static [DnsNsec3Record] Parse([byte[]]$rdata) {
		$r          = [DnsBinaryReader]::new($rdata)
		$algVal     = $r.ReadUInt8()
		$flagsval   = $r.ReadUInt8()
		$iterval    = $r.ReadUInt16BE()
		$saltLenval = $r.ReadUInt8()
		$saltval    = if ($saltLenval -gt 0) { $r.ReadBytes($saltLenval) } else { @() }

		$hashLenval  = $r.ReadUInt8()
		$nextHashval = $r.ReadBytes($hashLenval)

		$typesval = New-Object -TypeName System.Collections.Generic.List[int]
		while ($r.Position -lt $r.Buffer.Length) {
			$blockval = $r.ReadUInt8()
			$lenval   = $r.ReadUInt8()
			if ($lenval -lt 1 -or $lenval -gt 32) {
				throw "Invalid NSEC3 bitmap length: $lenval"
			}
			$bitsval  = $r.ReadBytes($lenval)
			for ($b = 0; $b -lt $bitsval.Length; $b++) {
				for ($bit = 0; $bit -lt 8; $bit++) {
					if ($bitsval[$b] -band (1 -shl (7-$bit))) {
						$null = $typesval.Add($blockval * 256 + $b*8 + $bit)
					}
				}
			}
		}

		return [DnsNsec3Record]::new($algVal,$flagsval,$iterval,$saltval,$nextHashval,$typesval.ToArray())
	}
    
	[byte[]]ToWire() {
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.HashAlgorithm)
		$w.WriteUInt8($this.Flags)
		$w.WriteUInt16BE($this.Iterations)

		if ($this.Salt -and $this.Salt.Length -gt 0) {
			$w.WriteUInt8([byte]$this.Salt.Length)
			$w.WriteBytes($this.Salt)
		}
		else {
			$w.WriteUInt8(0)
		}

		$w.WriteUInt8([byte]$this.NextHash.Length)
		$w.WriteBytes($this.NextHash)

		$byBlock = @{}
		foreach ($t in $this.Types) {
			$block  = [int]([math]::Floor($t / 256))
			$offset = $t % 256
			if (-not $byBlock.ContainsKey($block)) {
				$byBlock[$block] = New-Object -TypeName System.Collections.Generic.List[int]
			}
			$null = $byBlock[$block].Add($offset)
		}

		foreach ($kv in $byBlock.GetEnumerator() | Sort-Object -Property Key) {
			$block   = [byte]$kv.Key
			$offsets = $kv.Value | Sort-Object
			$maxByte = [int]([math]::Floor(($offsets | Measure-Object -Maximum).Maximum / 8))
			$bitmap  = New-Object -TypeName 'byte[]' -ArgumentList ($maxByte+1)

			foreach ($o in $offsets) {
				$b   = [int]([math]::Floor($o / 8))
				$bit = $o % 8
				$bitmap[$b] = $bitmap[$b] -bor (1 -shl (7-$bit))
			}

			$w.WriteUInt8($block)
			$w.WriteUInt8([byte]$bitmap.Length)
			$w.WriteBytes($bitmap)
		}

		return $w.ToArray()
	}
}

#endregion
# ============================================================



# ============================================================
#region 5. Resource Record Container (depends on all RDATA types)
# ============================================================

class DnsResourceRecord {
	[string] $Name
	[uint16] $Type
	[uint16] $Class
	[uint32] $Ttl
	[byte[]] $RawRData
	[object] $RDataObject

	DnsResourceRecord(
		[string]$name,
		[uint16]$type,
		[uint16]$class,
		[uint32]$ttl,
		[byte[]]$raw,
		[object]$obj
	) {
		$this.Name        = $name
		$this.Type        = $type
		$this.Class       = $class
		$this.Ttl         = $ttl
		$this.RawRData    = $raw
		$this.RDataObject = $obj
	}

	static [DnsResourceRecord] Parse([DnsBinaryReader]$r) {
		$nameValue     = $r.ReadName()
		$typeValue     = $r.ReadUInt16BE()
		$classValue    = $r.ReadUInt16BE()
		$ttlValue      = $r.ReadUInt32BE()
		$rdlengthValue = $r.ReadUInt16BE()

		$rdataValue = $null
		$objValue   = $null

		if ($typeValue -eq 2) {
			$rdataStart = $r.Position
			$nsName     = $r.ReadName()
			$rdataEnd   = $r.Position

			$rdataValue = $r.Buffer[$rdataStart..($rdataEnd - 1)]
			$objValue   = [DnsNsRecord]::new($nsName)
		}
		else {
			$rdataValue = $r.ReadBytes($rdlengthValue)
			$objValue   = [DnsResourceRecord]::ParseRDataTyped($typeValue, $rdataValue)
		}

		return [DnsResourceRecord]::new(
			$nameValue,
			$typeValue,
			$classValue,
			$ttlValue,
			$rdataValue,
			$objValue
		)
	}

	static [object] ParseRDataTyped([uint16]$type, [byte[]]$rdata) {
		switch ($type) {
			1   { return [DnsARecord]::Parse($rdata) }
			28  { return [DnsAaaaRecord]::Parse($rdata) }
			5   { return [DnsCnameRecord]::Parse($rdata) }
			15  { return [DnsMxRecord]::Parse($rdata) }
			16  { return [DnsTxtRecord]::Parse($rdata) }
			33  { return [DnsSrvRecord]::Parse($rdata) }
			48  { return [DnsDnskeyRecord]::Parse($rdata) }
			43  { return [DnsDsRecord]::Parse($rdata) }
			46  { return [DnsRrsigRecord]::Parse($rdata) }
			47  { return [DnsNsecRecord]::Parse($rdata) }
			50  { return [DnsNsec3Record]::Parse($rdata) }
			default { return $null }
		}
		return $null
	}

	[void] Write([DnsBinaryWriter]$w) {
		$w.WriteName($this.Name)
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
		$w.WriteUInt32BE($this.Ttl)
		$w.WriteUInt16BE([uint16]$this.RawRData.Length)
		$w.WriteBytes($this.RawRData)
	}

	[byte[]] ToCanonicalWire() {
		$w = [DnsBinaryWriter]::new()
		$w.WriteBytes( [byte[]](Get-DnssecCanonicalNameWire -Name $this.Name) )
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
		$w.WriteUInt32BE($this.Ttl)
		$w.WriteUInt16BE([uint16]$this.RawRData.Length)
		$w.WriteBytes($this.RawRData)
		return $w.ToArray()
	}
}

#endregion
# ============================================================



# ============================================================
#region 6. EDNS / OPT Record (used inside DnsPacket)
# ============================================================

class DnsOptRecord {
	[uint16]$UdpPayloadSize
	[byte]  $ExtendedRcode
	[byte]  $Version
	[uint16]$Flags
	[byte[]]$Options

	DnsOptRecord(
		[uint16]$udp,
		[byte]$rcode,
		[byte]$ver,
		[uint16]$flags,
		[byte[]]$opts
	) {
		$this.UdpPayloadSize = $udp
		$this.ExtendedRcode  = $rcode
		$this.Version        = $ver
		$this.Flags          = $flags
		$this.Options        = $opts
	}

	static [DnsOptRecord] Parse([DnsBinaryReader]$r) {
		$name = $r.ReadUInt8()
		if ($name -ne 0) { throw 'Invalid OPT NAME (must be root)' }

		$type = $r.ReadUInt16BE()
		if ($type -ne 41) { throw 'Invalid OPT TYPE' }

		$udpSizeval  = $r.ReadUInt16BE()
		$extRcodeval = $r.ReadUInt8()
		$versionval  = $r.ReadUInt8()
		$flagsval    = $r.ReadUInt16BE()
		$rdlenval    = $r.ReadUInt16BE()
		$optsval     = if ($rdlenval -gt 0) { $r.ReadBytes($rdlenval) } else { @() }

		return [DnsOptRecord]::new(
			$udpSizeval, $extRcodeval, $versionval, $flagsval, $optsval
		)
	}

	[void]Write([DnsBinaryWriter]$w) {
		$w.WriteUInt8(0)
		$w.WriteUInt16BE(41)
		$w.WriteUInt16BE($this.UdpPayloadSize)
		$w.WriteUInt8($this.ExtendedRcode)
		$w.WriteUInt8($this.Version)
		$w.WriteUInt16BE($this.Flags)
		$w.WriteUInt16BE($this.Options.Length)
		$w.WriteBytes($this.Options)
	}
}

#endregion
# ============================================================



# ============================================================
#region 7. DNS Packet Container (depends on everything above)
# ============================================================

class DnsPacket {
	[DnsHeader] $Header
	[System.Collections.Generic.List[DnsQuestion]] $Questions
	[System.Collections.Generic.List[DnsResourceRecord]] $Answers
	[System.Collections.Generic.List[DnsResourceRecord]] $Authority
	[System.Collections.Generic.List[DnsResourceRecord]] $Additional
	[DnsOptRecord] $Opt

	DnsPacket() {
		$this.Questions  = [System.Collections.Generic.List[DnsQuestion]]::new()
		$this.Answers    = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Authority  = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Additional = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Opt        = $null
	}

	static [DnsPacket] Parse([byte[]]$packetBytes) {
		$r = [DnsBinaryReader]::new($packetBytes)
		$pktval = [DnsPacket]::new()
		$pktval.Header = [DnsHeader]::Parse($r)

		for ($i = 0; $i -lt $pktval.Header.QdCount; $i++) {
			$null = $pktval.Questions.Add([DnsQuestion]::Parse($r))
		}

		for ($i = 0; $i -lt $pktval.Header.AnCount; $i++) {
			if ($r.Position -ge $r.Buffer.Length) {
				throw 'DNS header ANCOUNT exceeds packet length'
			}
			$null = $pktval.Answers.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pktval.Header.NsCount; $i++) {
			if ($r.Position -ge $r.Buffer.Length) {
				throw 'DNS header NSCOUNT exceeds packet length'
			}
			$null = $pktval.Authority.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pktval.Header.ArCount; $i++) {
			$saved = $r.Position
			$r.ReadName()
			$type = $r.ReadUInt16BE()
			$r.Position = $saved

			if ($type -eq 41) {
				if ($pktval.Opt) { throw 'Multiple OPT records not allowed' }
				$pktval.Opt = [DnsOptRecord]::Parse($r)
			}
			else {
				$null = $pktval.Additional.Add([DnsResourceRecord]::Parse($r))
			}
		}

		return $pktval
	}

	[byte[]] ToArray() {
		$w = [DnsBinaryWriter]::new()

		$optCount = if ($this.Opt) { 1 } else { 0 }
		$this.Header.ArCount = $this.Additional.Count + $optCount

		$this.Header.Write($w)

		foreach ($q in $this.Questions)  { $q.Write($w) }
		foreach ($rr in $this.Answers)   { $rr.Write($w) }
		foreach ($rr in $this.Authority) { $rr.Write($w) }
		foreach ($rr in $this.Additional){ $rr.Write($w) }

		if ($this.Opt) { $this.Opt.Write($w) }

		return $w.ToArray()
	}
}

#endregion
# ============================================================

# ============================================================
#region 8. DNS Transport Clients (DoT / DoH)
# ============================================================

class DnsDotClient {
		[string] $Server
		[int]    $Port

		DnsDotClient([string]$server, [int]$port = 853) {
				$this.Server = $server
				$this.Port   = $port
		}

		[DnsPacket] Query([DnsPacket]$packet) {

				$bytes = ConvertTo-DnsWireBytes -Packet $packet

				$respBytes = Invoke-DnsTransportSafe -Context "DoT query" -Operation {
						$tcp = New-Object System.Net.Sockets.TcpClient
						$tcp.Connect($this.Server, $this.Port)

						$ssl = New-Object System.Net.Security.SslStream(
								$tcp.GetStream(),
								$false,
								{ param($s,$c,$ch,$e) return $true }
						)
						$ssl.AuthenticateAsClient($this.Server)

						$lenBytes = [BitConverter]::GetBytes([uint16]$bytes.Length)
						if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }

						$ssl.Write($lenBytes, 0, 2)
						$ssl.Write($bytes, 0, $bytes.Length)
						$ssl.Flush()

						$lenBuf = New-Object byte[] 2
						$ssl.Read($lenBuf, 0, 2) | Out-Null
						if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBuf) }
						$respLen = [BitConverter]::ToUInt16($lenBuf, 0)

						$resp = New-Object byte[] $respLen
						$read = 0
						while ($read -lt $respLen) {
								$read += $ssl.Read($resp, $read, $respLen - $read)
						}

						$ssl.Close()
						$tcp.Close()

						return $resp
				}

				return ConvertFrom-DnsWireBytes -Bytes $respBytes
		}
}

class DnsDohClient {
		[string] $Endpoint

		DnsDohClient([string]$endpoint) {
				$this.Endpoint = $endpoint
		}

		[DnsPacket] Query([DnsPacket]$packet) {

				$bytes = ConvertTo-DnsWireBytes -Packet $packet

				$respBytes = Invoke-DnsTransportSafe -Context "DoH query" -Operation {
						$client = New-Object System.Net.Http.HttpClient
						$content = New-Object System.Net.Http.ByteArrayContent($bytes)
						$content.Headers.ContentType = 'application/dns-message'

						$response = $client.PostAsync($this.Endpoint, $content).Result
						if (-not $response.IsSuccessStatusCode) {
								throw "HTTP $($response.StatusCode)"
						}

						return $response.Content.ReadAsByteArrayAsync().Result
				}

				return ConvertFrom-DnsWireBytes -Bytes $respBytes
		}
}


#endregion
# ============================================================

# ============================================================
#region 9. Transport Helper Functions
# ============================================================



#endregion
# ============================================================

function ConvertTo-DnsWireBytes {
		param(
				[Parameter(Mandatory)]
				[DnsPacket]$Packet
		)

		return $Packet.ToArray()
}

function ConvertFrom-DnsWireBytes {
		param(
				[Parameter(Mandatory)]
				[byte[]]$Bytes
		)

		return [DnsPacket]::Parse($Bytes)
}

function Invoke-DnsTransportSafe {
		param(
				[Parameter(Mandatory)]
				[ScriptBlock]$Operation,

				[string]$Context = "DNS transport"
		)

		try {
				return & $Operation
		}
		catch {
				throw "$Context failed: $($_.Exception.Message)"
		}
}

function Parse-DnsHeader 
{
	param(
		[byte[]]$Packet
	)

	$r = [DnsBinaryReader]::new($Packet)
	return [DnsHeader]::Parse($r)
}

function Parse-DnsQuestion 
{
	param(
		[byte[]]$Packet,
		[ref]$offset
	)

	$r = [DnsBinaryReader]::new($Packet)
	$r.Position = $offset.Value

	$q = [DnsQuestion]::Parse($r)
	$offset.Value = $r.Position

	return $q
}

function Parse-DnsPacket 
{
	param(
		[byte[]]$Packet
	)

	return [DnsPacket]::Parse($Packet)
}

function Parse-A 
{
	param(
		[byte[]]$rdata,
		$Packet,
		[int]$offset
	)

	return [DnsARecord]::Parse($rdata)
}

function Parse-TXT 
{
	param(
		[byte[]]$rdata,
		$Packet,
		[int]$offset
	)

	return [DnsTxtRecord]::Parse($rdata)
}

function Parse-DNSKEY 
{
	param(
		[byte[]]$rdata,
		$Packet,
		[int]$offset
	)

	return [DnsDnskeyRecord]::Parse($rdata)
}

function Parse-NSEC 
{
	param(
		[byte[]]$rdata,
		$Packet,
		[int]$offset
	)

	return [DnsNsecRecord]::Parse($rdata)
}

function Invoke-DnsUdpQuery 
{
	param(
		[string]$server,
		[byte[]]$query,
		[int]$port = 53,
		[int]$TimeoutMs = 3000
	)

	$udp = New-Object -TypeName System.Net.Sockets.UdpClient
	$udp.Client.ReceiveTimeout = $TimeoutMs

	try 
	{
		$udp.Connect($server, $port)
		$null = $udp.Send($query, $query.Length)

		$remote = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Any, 0)
		$resp = $udp.Receive([ref]$remote)
		return $resp
	}
	finally 
	{$udp.Close()}
}


function New-DnsQueryPacket 
{
	param(
		[string]$name,
		[int]$type = 1,
		[switch]$DoBit
	)

	$pkt = [DnsPacket]::new()
	$pkt.Header = [DnsHeader]::new(
		(Get-Random -Minimum 0 -Maximum 65535),
		0x0100,
		1, 0, 0, 0
	)

	$pkt.Questions.Add(
		[DnsQuestion]::new($name, $type, 1)
	)

	if ($DoBit) 
	{
		$opt = [DnsOptRecord]::new(
			4096,
			0,
			0,
			0x8000,
			@()
		)
		$pkt.Opt = $opt
	}

	return $pkt.ToArray()
}

function Resolve-DnsIterative 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$name,

		[Parameter(Mandatory)]
		[int]$type,

		[Parameter(Mandatory)]
		[string[]]$RootServers
	)

	$fqdn = $name.TrimEnd('.').ToLower()

	# Start at the roots, but we will never go back to them
	$currentServers = $RootServers | Sort-Object -Unique

	# Track server sets to avoid cycles
	$visitedServerSets = New-Object -TypeName System.Collections.Generic.HashSet[string]

	$maxIterations = 40
	$iteration = 0

	while ($iteration++ -lt $maxIterations) 
	{
		# Detect server-set cycles
		$setKey = ($currentServers -join ',')
		if ($visitedServerSets.Contains($setKey)) 
		{
			return [pscustomobject]@{
				Status = 'BailOut'
				Reason = "Server-set cycle detected: $setKey"
			}
		}
		$visitedServerSets.Add($setKey)

		$jumpToNextIteration = $false

		foreach ($server in $currentServers) 
		{
			try 
			{
				$query = New-DnsQueryPacket -Name $fqdn -Type $type -DoBit
				$bytes = Invoke-DnsUdpQuery -Server $server -Query $query
				$resp  = Parse-DnsPacket -Packet $bytes

				# 1. Final answer?
				if ($resp.Answers.Count -gt 0) 
				{
					return [pscustomobject]@{
						Status   = 'Final'
						Response = $resp
						Reason   = "Answer found from $server"
					}
				}

				# 2. Prefer glue (A/AAAA) if present
				$glue = $resp.Additional | Where-Object -FilterScript {$_.Type -in 1, 28}
				if ($glue.Count -gt 0) 
				{
					$newServers = $glue |
					ForEach-Object -Process {
						if ($_.RDataObject -and $_.RDataObject.PSObject.Properties['Address']) 
						{$_.RDataObject.Address}
					} |
					Where-Object -FilterScript {$_} |
					Sort-Object -Unique

					if ($newServers.Count -gt 0) 
					{
						$currentServers = $newServers
						$jumpToNextIteration = $true
						break
					}
				}

				# 3. NS referrals (no glue or incomplete glue)
				$nsRecords = $resp.Authority | Where-Object -FilterScript {$_.Type -eq 2}
				if ($nsRecords.Count -gt 0) 
				{
					$nsNames = $nsRecords |
					ForEach-Object -Process {
						if ($_.RDataObject -and $_.RDataObject.PSObject.Properties['NsName']) 
						{$_.RDataObject.NsName}
					} |
					Where-Object -FilterScript {$_} |
					Sort-Object -Unique

					if ($nsNames.Count -gt 0) 
					{
						$resolved = foreach ($nsName in $nsNames) 
						{Resolve-NameserverAddress -NsName $nsName -BootstrapServers $RootServers}

						$resolved = $resolved |
						Where-Object -FilterScript {$_} |
						Sort-Object -Unique

						if ($resolved.Count -gt 0) 
						{
							$currentServers = $resolved
							$jumpToNextIteration = $true
							break
						}
					}
				}
			}
			catch 
			{# Ignore this server, try next
			}
		}

		if ($jumpToNextIteration) 
		{continue   # new $currentServers, next hop
		}

		# If we reach here, all servers in this set failed or gave unusable referrals
		return [pscustomobject]@{
			Status = 'BailOut'
			Reason = 'All servers in current set failed or gave no usable referrals'
		}
	}

	return [pscustomobject]@{
		Status = 'BailOut'
		Reason = "Max iterations ($maxIterations) reached"
	}
}

function Resolve-NameserverAddress 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$nsName,

		[Parameter(Mandatory)]
		[string[]]$BootstrapServers
	)

	$target = $nsName.TrimEnd('.').ToLower()

	# Start at the roots
	$currentServers = $BootstrapServers | Sort-Object -Unique

	# Avoid cycles on server sets and NS names
	$visitedServerSets = New-Object -TypeName System.Collections.Generic.HashSet[string]
	$visitedNsNames    = New-Object -TypeName System.Collections.Generic.HashSet[string]

	$maxIterations = 40
	$iteration = 0

	while ($iteration++ -lt $maxIterations) 
	{
		# Detect server-set cycles
		$setKey = ($currentServers -join ',')
		if ($visitedServerSets.Contains($setKey)) 
		{return $null}
		$null = $visitedServerSets.Add($setKey)

		foreach ($server in $currentServers) 
		{
			try 
			{
				# Ask for A and AAAA; A first
				$answers = New-Object -TypeName System.Collections.Generic.List[string]

				foreach ($qType in 1, 28) 
				{
					$query = New-DnsQueryPacket -Name $target -Type $qType -DoBit
					$bytes = Invoke-DnsUdpQuery -Server $server -Query $query
					$resp  = Parse-DnsPacket -Packet $bytes

					foreach ($rr in $resp.Answers) 
					{
						if ($rr.Type -in 1, 28 -and $rr.RDataObject -and $rr.RDataObject.Address) 
						{$null = $answers.Add($rr.RDataObject.Address)}
					}
				}

				if ($answers.Count -gt 0) 
				{return ($answers | Sort-Object -Unique)}

				# No direct A/AAAA; look for NS referrals
				$nsRecords = $resp.Authority | Where-Object -FilterScript {$_.Type -eq 2}
				if ($nsRecords.Count -eq 0) 
				{continue}

				# Extract NS names from typed RDATA
				$nsNames = $nsRecords |
				ForEach-Object -Process {
					if ($_.RDataObject -and $_.RDataObject.NsName) 
					{$_.RDataObject.NsName}
				} |
				Where-Object -FilterScript {$_} |
				Sort-Object -Unique

				if ($nsNames.Count -eq 0) 
				{continue}

				# Prefer glue in Additional
				$glueAddrs = $resp.Additional |
				Where-Object -FilterScript {$_.Type -in 1, 28} |
				ForEach-Object -Process {
					if ($_.RDataObject -and $_.RDataObject.Address) 
					{$_.RDataObject.Address}
				} |
				Where-Object -FilterScript {$_} |
				Sort-Object -Unique

				if ($glueAddrs.Count -gt 0) 
				{
					$currentServers = $glueAddrs
					break
				}

				# No glue: resolve NS names themselves using the same bootstrap logic
				$resolvedNsAddrs = New-Object -TypeName System.Collections.Generic.List[string]

				foreach ($ns in $nsNames) 
				{
					$nsKey = $ns.TrimEnd('.').ToLower()
					if ($visitedNsNames.Contains($nsKey)) 
					{continue}
					$null = $visitedNsNames.Add($nsKey)

					$nsAddrs = Resolve-NameserverAddress -NsName $ns -BootstrapServers $BootstrapServers
					if ($nsAddrs) 
					{
						foreach ($a in $nsAddrs) 
						{
							if (-not [string]::IsNullOrWhiteSpace($a)) 
							{$null = $resolvedNsAddrs.Add($a)}
						}
					}
				}

				if ($resolvedNsAddrs.Count -gt 0) 
				{
					$currentServers = ($resolvedNsAddrs | Sort-Object -Unique)
					break
				}
			}
			catch 
			{# try next server in current set
			}
		}
	}

	return $null
}


#endregion
# ============================================================


# ============================================================
#region 10. DNSSEC Canonicalization
# ============================================================

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


function Get-DnssecCanonicalRrWire 
{
	param(
		[Parameter(Mandatory)]$rr
	)

	$w = [DnsBinaryWriter]::new()
	$w.WriteBytes([byte[]](Get-DnssecCanonicalNameWire -Name $rr.Name))
	$w.WriteUInt16BE([uint16]$rr.Type)
	$w.WriteUInt16BE([uint16]$rr.Class)
	$w.WriteUInt32BE([uint32]$rr.TTL)

	$rdata = $rr.RawRData
	$w.WriteUInt16BE([uint16]$rdata.Length)
	$w.WriteBytes($rdata)

	return $w.ToArray()
}

function Get-DnssecCanonicalRrsetData 
{
	param(
		[DnsResourceRecord[]]$Rrset
	)

	if (-not $Rrset -or $Rrset.Count -eq 0) 
	{throw 'RRset is empty.'}

	$name  = $Rrset[0].Name
	$type  = [uint16]$Rrset[0].Type
	$class = [uint16]$Rrset[0].Class

	$records = @()
	foreach ($rr in $Rrset) 
	{
		if ($rr.Name -ne $name -or $rr.Type -ne $type -or $rr.Class -ne $class) 
		{throw 'Mixed RRset: all records must share name, type, class.'}

		$rdataWire = $rr.RawRData
		$records += ,@{
			RdataWire = $rdataWire
			RdataKey  = [System.BitConverter]::ToString($rdataWire)
		}
	}

	$sorted = $records | Sort-Object -Property RdataKey

	return $sorted
}

function Get-DnssecSignedData 
{
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$Rrset
	)

	$bytes = New-Object -TypeName System.Collections.Generic.List[byte]

	# Type Covered
	$tc = [BitConverter]::GetBytes([uint16]$Rrsig.TypeCovered)
	if ([BitConverter]::IsLittleEndian) 
	{[Array]::Reverse($tc)}
	$bytes.AddRange($tc)

	# Algorithm, Labels
	$bytes.Add([byte]$Rrsig.Algorithm)
	$bytes.Add([byte]$Rrsig.Labels)

	# Original TTL
	$ttlBytes = [BitConverter]::GetBytes([uint32]$Rrsig.OriginalTTL)
	if ([BitConverter]::IsLittleEndian) 
	{[Array]::Reverse($ttlBytes)}
	$bytes.AddRange($ttlBytes)

	# Expiration, Inception
	foreach ($val in @($Rrsig.Expiration, $Rrsig.Inception)) 
	{
		$t = [BitConverter]::GetBytes([uint32]$val)
		if ([BitConverter]::IsLittleEndian) 
		{[Array]::Reverse($t)}
		$bytes.AddRange($t)
	}

	# Key Tag
	$kt = [BitConverter]::GetBytes([uint16]$Rrsig.KeyTag)
	if ([BitConverter]::IsLittleEndian) 
	{[Array]::Reverse($kt)}
	$bytes.AddRange($kt)

	# Signer Name (canonical)
	$bytes.AddRange( [byte[]](Get-DnssecCanonicalNameWire -Name $Rrsig.SignerName) )

	# Canonical RRset
	$sorted = Get-DnssecCanonicalRrsetData -Rrset $Rrset

	$nameWire = [byte[]](Get-DnssecCanonicalNameWire -Name $Rrset[0].Name)
	$type  = [uint16]$Rrset[0].Type
	$class = [uint16]$Rrset[0].Class

	$typeBytes  = [BitConverter]::GetBytes($type)
	$classBytes = [BitConverter]::GetBytes($class)
	if ([BitConverter]::IsLittleEndian) 
	{
		[Array]::Reverse($typeBytes)
		[Array]::Reverse($classBytes)
	}

	foreach ($rec in $sorted) 
	{
		$rdataWire = $rec.RdataWire

		# Owner name
		$bytes.AddRange($nameWire)

		# Type, Class
		$bytes.AddRange($typeBytes)
		$bytes.AddRange($classBytes)

		# TTL (Original TTL)
		$ttlBytes = [BitConverter]::GetBytes([uint32]$Rrsig.OriginalTTL)
		if ([BitConverter]::IsLittleEndian) 
		{[Array]::Reverse($ttlBytes)}
		$bytes.AddRange($ttlBytes)

		# RDLENGTH
		$rdlengthBytes = [BitConverter]::GetBytes([uint16]$rdataWire.Length)
		if ([BitConverter]::IsLittleEndian) 
		{[Array]::Reverse($rdlengthBytes)}
		$bytes.AddRange($rdlengthBytes)

		# RDATA
		$bytes.AddRange($rdataWire)
	}

	return $bytes.ToArray()
}


#endregion
# ============================================================

# ============================================================
#region 11. DNSSEC Cryptographic
# ============================================================

function Get-DnssecSigningKey 
{
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$DnskeyRrset
	)

	$candidates = $DnskeyRrset |
	Where-Object -FilterScript {
		$_.Type -eq 48 -and $_.RData -is [DnsDnskeyRecord] -and
		$_.RData.KeyTag -eq $Rrsig.KeyTag -and
		$_.RData.Algorithm -eq $Rrsig.Algorithm
	}

	return $candidates | Select-Object -First 1
}

function Test-DnssecRrsig 
{
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$Rrset,
		[DnsResourceRecord[]]$DnskeyRrset
	)

	if (-not (Test-DnssecTimeWindow -Rrsig $Rrsig)) 
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = 'RRSIG not valid at current time'
		}
	}

	$dnskeyRR = Get-DnssecSigningKey -Rrsig $Rrsig -DnskeyRrset $DnskeyRrset
	if (-not $dnskeyRR) 
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = "No matching DNSKEY for key tag $($Rrsig.KeyTag)"
		}
	}
	$Dnskey = [DnsDnskeyRecord]$dnskeyRR.RData

	$SignedData = Get-DnssecSignedData -Rrsig $Rrsig -Rrset $Rrset

	$ok = Test-DnssecSignature -SignedData $SignedData -Rrsig $Rrsig -Dnskey $Dnskey

	return [pscustomobject]@{
		Valid  = $ok
		Reason = if ($ok) 
		{'OK'}
		else 
		{'Cryptographic signature check failed'}
	}
}

function Get-DnssecKeyDigest 
{
	param(
		[string]$OwnerName,
		[DnsDnskeyRecord]$Dnskey,
		[int]$DigestType
	)

	# Canonical owner name
	$nameWire = [byte[]](Get-DnssecCanonicalNameWire -Name $OwnerName)

	# Build DNSKEY RDATA in canonical form
	$rdata = New-Object -TypeName System.Collections.Generic.List[byte]

	$flagsBytes = [BitConverter]::GetBytes([uint16]$Dnskey.Flags)
	if ([BitConverter]::IsLittleEndian) 
	{[Array]::Reverse($flagsBytes)}
	$rdata.AddRange([byte[]]$flagsBytes)

	$rdata.Add([byte]$Dnskey.Protocol)
	$rdata.Add([byte]$Dnskey.Algorithm)

	# Public key - force to byte[]
	$rdata.AddRange([byte[]]$Dnskey.PublicKey)

	# Combine name + RDATA for digest input
	$full = New-Object -TypeName System.Collections.Generic.List[byte]
	$full.AddRange([byte[]]$nameWire)
	$full.AddRange([byte[]]$rdata.ToArray())

	$data = [byte[]]$full.ToArray()

	switch ($DigestType) {
		1 
		{return [System.Security.Cryptography.SHA1]::Create().ComputeHash($data)}
		2 
		{return [System.Security.Cryptography.SHA256]::Create().ComputeHash($data)}
		4 
		{return [System.Security.Cryptography.SHA384]::Create().ComputeHash($data)}
		default 
		{throw "Unsupported DS digest type: $DigestType"}
	}
}

function Test-DnssecSignature 
{
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$Rrset,
		[DnsDnskeyRecord]$Dnskey
	)

	$SignedData = Get-DnssecSignedData -Rrsig $Rrsig -Rrset $Rrset

	switch ($Dnskey.Algorithm) {
		8 
		{
			$rsa = [System.Security.Cryptography.RSA]::Create()
			$rsa.ImportSubjectPublicKeyInfo($Dnskey.PublicKey, [ref]0)
			return $rsa.VerifyData(
				$SignedData,
				$Rrsig.Signature,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256,
				[System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			)
		}
		13 
		{
			$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
			$ecdsa.ImportSubjectPublicKeyInfo($Dnskey.PublicKey, [ref]0)
			return $ecdsa.VerifyData(
				$SignedData,
				$Rrsig.Signature,
				[System.Security.Cryptography.HashAlgorithmName]::SHA256
			)
		}
		default 
		{throw "Unsupported DNSSEC algorithm: $($Dnskey.Algorithm)"}
	}
}

function Get-DnssecKeyDigestHex 
{
	param(
		[string]$OwnerName,
		[DnsDnskeyRecord]$Dnskey,
		[int]$DigestType
	)

	# Compute raw digest bytes
	$digest = [byte[]](Get-DnssecKeyDigest `
		-OwnerName $OwnerName `
		-Dnskey $Dnskey `
	-DigestType $DigestType)

	# Convert to lowercase hex without widening
	$sb = New-Object -TypeName System.Text.StringBuilder
	foreach ($b in $digest) 
	{[void]$sb.AppendFormat('{0:x2}', $b)}

	return $sb.ToString()
}

function Test-DnssecDsForDnskey 
{
	param(
		[psobject[]]$DsRrset,
		[psobject[]]$DnskeyRrset,
		[string]$ChildZoneName
	)

	$results = @()

	foreach ($dsObj in $DsRrset) 
	{
		$ds = $dsObj.RData
		$match = $false

		foreach ($keyObj in $DnskeyRrset) 
		{
			$Dnskey = $keyObj.RData

			if ($Dnskey.KeyTag -ne $ds.KeyTag) 
			{continue}
			if ($Dnskey.Algorithm -ne $ds.Algorithm) 
			{continue}

			$digest = Get-DnssecKeyDigest -OwnerName $ChildZoneName -Dnskey $Dnskey -DigestType $ds.DigestType

			if ($digest.SequenceEqual($ds.Digest)) 
			{
				$match = $true
				break
			}
		}

		$results += [pscustomobject]@{
			DsRecord = $ds
			Valid    = $match
		}
	}

	return $results
}

function Test-DnssecChain 
{
	param(
		[DnsResourceRecord[]]$DnskeyRrset,
		[DnsResourceRecord[]]$DsRrset,
		[DnsResourceRecord[]]$RrsigRrset,
		[string]$ZoneName
	)

	$dnskeys = $DnskeyRrset | ForEach-Object -Process {$_.RData}
	$dsRecords = $DsRrset | ForEach-Object -Process {$_.RData}
	$rrsigs = $RrsigRrset | ForEach-Object -Process {$_.RData}

	$dsCheck = Test-DnssecDsForDnskey -DsRrset $DsRrset -DnskeyRrset $DnskeyRrset -ChildZoneName $ZoneName

	if (-not ($dsCheck.Valid -contains $true)) 
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = 'No DNSKEY matches DS'
		}
	}

	foreach ($sigObj in $RrsigRrset) 
	{
		$sig = $sigObj.RData
		$key = $dnskeys |
		Where-Object -FilterScript {$_.KeyTag -eq $sig.KeyTag -and $_.Algorithm -eq $sig.Algorithm} |
		Select-Object -First 1

		if (-not $key) 
		{
			return [pscustomobject]@{
				Valid  = $false
				Reason = 'No matching DNSKEY for RRSIG'
			}
		}

		$ok = Test-DnssecRrsig -Rrsig $sig -Rrset $DnskeyRrset -DnskeyRrset $key
		if (-not $ok) 
		{
			return [pscustomobject]@{
				Valid  = $false
				Reason = 'RRSIG validation failed'
			}
		}
	}

	return [pscustomobject]@{
		Valid  = $true
		Reason = 'DNSSEC chain validated'
	}
}

function Test-DnssecTimeWindow 
{
	param(
		[DnsRrsigRecord]$Rrsig
	)

	$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

	if ($now -lt $Rrsig.Inception) 
	{return $false}

	if ($now -gt $Rrsig.Expiration) 
	{return $false}

	return $true
}

#endregion
# ============================================================

# ============================================================
#region 12. DNSSEC High‑Level Resolver
# ============================================================

function Resolve-Dnssec 
{
	param(
		[string]$name,
		[int]$type = 1,
		[string[]]$RootServers = @(
			'198.41.0.4', 
			'199.9.14.201', 
			'192.33.4.12', 
			'199.7.91.13', 
			'192.203.230.10', 
			'192.5.5.241', 
			'192.112.36.4', 
			'198.97.190.53', 
			'192.36.148.17', 
			'192.58.128.30', 
			'193.0.14.129', 
			'199.7.83.42', 
			'202.12.27.33'
		)
	)

	$iter = Resolve-DnsIterative -Name $name -Type $type -RootServers $RootServers

	if ($iter.Status -ne 'Final') 
	{
		return [pscustomobject]@{
			Valid   = $false
			Reason  = "Iterative resolution failed: $($iter.Reason)"
			Answer  = $null
			Rrsigs  = @()
			Dnskeys = @()
		}
	}

	$resp = $iter.Response

	$answers = $resp.Answers
	$rrsigs  = $resp.Answers | Where-Object -FilterScript {$_.Type -eq 46}
	$dnskeys = $resp.Additional | Where-Object -FilterScript {$_.Type -eq 48}

	if ($answers.Count -eq 0) 
	{
		return [pscustomobject]@{
			Valid   = $false
			Reason  = 'No answers returned'
			Answer  = $null
			Rrsigs  = $rrsigs
			Dnskeys = $dnskeys
		}
	}

	if ($rrsigs.Count -eq 0) 
	{
		return [pscustomobject]@{
			Valid   = $false
			Reason  = 'No RRSIGs returned'
			Answer  = $answers
			Rrsigs  = @()
			Dnskeys = $dnskeys
		}
	}

	if ($dnskeys.Count -eq 0) 
	{
		return [pscustomobject]@{
			Valid   = $false
			Reason  = 'No DNSKEYs returned'
			Answer  = $answers
			Rrsigs  = $rrsigs
			Dnskeys = @()
		}
	}

	foreach ($sig in $rrsigs) 
	{
		$Rrsig = $sig.RData
		$key = $dnskeys |
		Where-Object -FilterScript {$_.RData.KeyTag -eq $Rrsig.KeyTag -and $_.RData.Algorithm -eq $Rrsig.Algorithm} |
		Select-Object -First 1

		if (-not $key) 
		{
			return [pscustomobject]@{
				Valid   = $false
				Reason  = 'No matching DNSKEY for RRSIG'
				Answer  = $answers
				Rrsigs  = $rrsigs
				Dnskeys = $dnskeys
			}
		}

		$ok = Test-DnssecRrsig -Rrsig $Rrsig -Rrset $answers -DnskeyRrset $key.RData
		if (-not $ok) 
		{
			return [pscustomobject]@{
				Valid   = $false
				Reason  = 'RRSIG validation failed'
				Answer  = $answers
				Rrsigs  = $rrsigs
				Dnskeys = $dnskeys
			}
		}
	}

	return [pscustomobject]@{
		Valid   = $true
		Reason  = 'DNSSEC validation succeeded'
		Answer  = $answers
		Rrsigs  = $rrsigs
		Dnskeys = $dnskeys
	}
}

function Resolve-DnssecName 
{
	param(
		[string]$name,
		[int]$type = 1
	)

	return Resolve-Dnssec -Name $name -Type $type
}

function Test-DnssecName 
{
	param(
		[string]$name,
		[int]$type = 1
	)

	$result = Resolve-DnssecName -Name $name -Type $type
	return $result.Valid
}

function Format-DnssecResult 
{
	param(
		[psobject]$result
	)

	if (-not $result) 
	{return 'No result'}

	$status = if ($result.Valid) 
	{'VALID'}
	else 
	{'BOGUS'}

	$msg = "DNSSEC Status: $status`nReason: $($result.Reason)"

	if ($result.Answer) 
	{
		$msg += "`nAnswers:`n"
		foreach ($a in $result.Answer) 
		{$msg += "  $($a.Name) $($a.Type) $($a.RDataObject)`n"}
	}

	return $msg
}

#endregion
# ============================================================

# ============================================================
#region 13. Trust Anchor Management
# ============================================================

function Add-DnssecTrustAnchor 
{
	param(
		[string]$Zone,
		[uint16]$keyTag,
		[byte]$Algorithm,
		[byte]$DigestType,
		[string]$DigestHex
	)

	if (-not $script:TrustAnchors) 
	{$script:TrustAnchors = @{}}

	$script:TrustAnchors[$Zone] = [pscustomobject]@{
		KeyTag     = $keyTag
		Algorithm  = $Algorithm
		DigestType = $DigestType
		DigestHex  = $DigestHex.ToLower()
	}
}

function Get-DnssecTrustAnchors 
{
	if (-not $script:TrustAnchors) 
	{return @()}

	return $script:TrustAnchors.GetEnumerator() | ForEach-Object -Process {
		[pscustomobject]@{
			Zone       = $_.Key
			KeyTag     = $_.Value.KeyTag
			Algorithm  = $_.Value.Algorithm
			DigestType = $_.Value.DigestType
			DigestHex  = $_.Value.DigestHex
		}
	}
}

function Import-DnssecTrustAnchors 
{
	param(
		[string]$Path
	)

	if (-not (Test-Path $Path)) 
	{throw "Trust anchor file not found: $Path"}

	# Always initialize the table
	if (-not $script:TrustAnchors) 
	{$script:TrustAnchors = @{}}

	$json = Get-Content -Raw -Path $Path | ConvertFrom-Json

	foreach ($anchor in $json) 
	{
		# Basic validation
		if (-not $anchor.Zone)        
		{continue}
		if (-not $anchor.KeyTag)      
		{continue}
		if (-not $anchor.Algorithm)   
		{continue}
		if (-not $anchor.DigestType)  
		{continue}
		if (-not $anchor.DigestHex)   
		{continue}

		# Normalize zone name
		$Zone = $anchor.Zone.Trim().ToLower()
		if ($Zone -eq '') 
		{$Zone = '.'}

		# Insert validated anchor
		$script:TrustAnchors[$Zone] = @{
			KeyTag     = [int]$anchor.KeyTag
			Algorithm  = [int]$anchor.Algorithm
			DigestType = [int]$anchor.DigestType
			DigestHex  = $anchor.DigestHex.ToLower()
		}
	}
}

function Test-DnssecAnchoredDnskey 
{
	param(
		[string]$Zone,
		[DnsDnskeyRecord]$Dnskey
	)

	if (-not $script:TrustAnchors.ContainsKey($Zone)) 
	{return $false}

	$anchor = $script:TrustAnchors[$Zone]

	# HARDENING GOES HERE
	if ($null -eq $anchor) 
	{return $false}

	if ($Dnskey.KeyTag -ne $anchor.KeyTag) 
	{return $false}
	if ($Dnskey.Algorithm -ne $anchor.Algorithm) 
	{return $false}

	$digest = Get-DnssecKeyDigestHex -OwnerName $Zone -Dnskey $Dnskey -DigestType $anchor.DigestType

	return ($digest -eq $anchor.DigestHex)
}
function Initialize-DnssecTrustAnchors 
{
	$trustAnchorPath = Join-Path -Path $PSScriptRoot -ChildPath 'trust-anchors.json'
	Import-DnssecTrustAnchors -Path $trustAnchorPath
}


#endregion
# ============================================================

# ============================================================
#region xx. Transport Helper Functions
# ============================================================



#endregion
# ============================================================
