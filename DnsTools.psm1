#requires -Version 5.0

Set-StrictMode -Version Latest

# ============================================================
# Load Classes
# ============================================================

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

            # Move pos to the pointer target, but DO NOT advance $this.Position yet
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

    # Update the main reader position to where the name ended
    $this.Position = $pos

    return ($labels -join '.')
}
}
class DnsHeader {
	[uint16]$Id
	[uint16]$Flags
	[uint16]$QdCount
	[uint16]$AnCount
	[uint16]$NsCount
	[uint16]$ArCount

	DnsHeader([uint16]$id, [uint16]$flags, [uint16]$qd, [uint16]$an, [uint16]$ns, [uint16]$ar) 
	{
		$this.Id      = $id
		$this.Flags   = $flags
		$this.QdCount = $qd
		$this.AnCount = $an
		$this.NsCount = $ns
		$this.ArCount = $ar
	}

	static [DnsHeader] Parse([DnsBinaryReader]$r) 
	{
		$idValue      = $r.ReadUInt16BE()
		$flagsValue   = $r.ReadUInt16BE()
		$qdValue      = $r.ReadUInt16BE()
		$anValue      = $r.ReadUInt16BE()
		$nsValue      = $r.ReadUInt16BE()
		$arValue      = $r.ReadUInt16BE()
		return [DnsHeader]::new($idValue, $flagsValue, $qdValue, $anValue, $nsValue, $arValue)
	}

	[void]Write([DnsBinaryWriter]$w) 
	{
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

	DnsQuestion([string]$name, [uint16]$type, [uint16]$class) 
	{
		$this.Name  = $name
		$this.Type  = $type
		$this.Class = $class
	}

	static [DnsQuestion] Parse([DnsBinaryReader]$r) 
	{
		$nameValue  = $r.ReadName()
		$typeValue  = $r.ReadUInt16BE()
		$classValue = $r.ReadUInt16BE()
		return [DnsQuestion]::new($nameValue, $typeValue, $classValue)
	}

	[void]Write([DnsBinaryWriter]$w) 
	{
		$w.WriteName($this.Name)
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
	}
}
class DnsARecord {
	[string]$Address
	static [DnsARecord] Parse([byte[]]$rdata) 
	{
		return [DnsARecord]@{
			Address = ([System.Net.IPAddress]::new($rdata)).ToString()
		}
	}
}
class DnsAaaaRecord {
	[string]$Address
	static [DnsAaaaRecord] Parse([byte[]]$rdata) 
	{
		return [DnsAaaaRecord]@{
			Address = ([System.Net.IPAddress]::new($rdata)).ToString()
		}
	}
}
class DnsCnameRecord {
	[string]$Target

	DnsCnameRecord([string]$target) 
	{$this.Target = $target}

	static [DnsCnameRecord] Parse([DnsBinaryReader]$r, [int]$len) 
	{
		$start = $r.Position
		$name = $r.ReadName()
		return [DnsCnameRecord]::new($name)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.Target)
		return $w.ToArray()
	}
}
class DnsMxRecord {
	[uint16]$Preference
	[string]$Exchange

	DnsMxRecord([uint16]$pref, [string]$exch) 
	{
		$this.Preference = $pref
		$this.Exchange   = $exch
	}

	static [DnsMxRecord] Parse([DnsBinaryReader]$r, [int]$len) 
	{
		$prefVal = $r.ReadUInt16BE()
		$exchVal = $r.ReadName()
		return [DnsMxRecord]::new($prefVal, $exchVal)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Preference)
		$w.WriteName($this.Exchange)
		return $w.ToArray()
	}
}
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
class DnsSrvRecord {
	[uint16]$Priority
	[uint16]$Weight
	[uint16]$Port
	[string]$Target

	DnsSrvRecord([uint16]$pri,[uint16]$wgt,[uint16]$port,[string]$target) 
	{
		$this.Priority = $pri
		$this.Weight   = $wgt
		$this.Port     = $port
		$this.Target   = $target
	}

	static [DnsSrvRecord] Parse([DnsBinaryReader]$r, [int]$len)
 
	{
		$prival  = $r.ReadUInt16BE()
		$wgtval  = $r.ReadUInt16BE()
		$portval = $r.ReadUInt16BE()
		$tgtval  = $r.ReadName()
		return [DnsSrvRecord]::new($prival,$wgtval,$portval,$tgtval)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Priority)
		$w.WriteUInt16BE($this.Weight)
		$w.WriteUInt16BE($this.Port)
		$w.WriteName($this.Target)
		return $w.ToArray()
	}
}
class DnsNsRecord {
	[string]$NsName

	DnsNsRecord([string]$name) 
	{$this.NsName = $name}

	static [DnsNsRecord] Parse([DnsBinaryReader]$r, [int]$len) 
	{
		$name = $r.ReadName()
		return [DnsNsRecord]::new($name)
	}
}
class DnsDnskeyRecord {
	[uint16]$Flags
	[byte]  $Protocol
	[byte]  $Algorithm
	[byte[]]$PublicKey
	[uint16]$KeyTag
    
	DnsDnskeyRecord([uint16]$flags,[byte]$proto,[byte]$alg,[byte[]]$key) 
	{
		$this.Flags     = $flags
		$this.Protocol  = $proto
		$this.Algorithm = $alg
		$this.PublicKey = $key
		$this.KeyTag = [DnsDnskeyRecord]::ComputeKeyTag($flags, $proto, $alg, $key)
	}
    
	static [DnsDnskeyRecord] Parse([byte[]]$rdata) 
	{
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
	) 
	{
		$sum = 0
		$rdata = New-Object -TypeName System.Collections.Generic.List[byte]

		$flagsBytes = [BitConverter]::GetBytes($flags)
		if ([BitConverter]::IsLittleEndian) 
		{[Array]::Reverse($flagsBytes)}
		$rdata.AddRange($flagsBytes)

		$rdata.Add($proto)
		$rdata.Add($alg)
		$rdata.AddRange($key)

		$i = 0
		foreach ($b in $rdata) 
		{
			if ($i % 2 -eq 0) 
			{$sum += $b * 256}
			else 
			{$sum += $b}
			$i++
		}

		# Proper carry fold: (sum & 0xFFFF) + (sum >> 16)
		$sum = ($sum -band 0xFFFF) + ($sum -shr 16)

		return [uint16]($sum -band 0xFFFF)
	}
}
class DnsDsRecord {
	[uint16]$KeyTag
	[byte]  $Algorithm
	[byte]  $DigestType
	[byte[]]$Digest

	DnsDsRecord([uint16]$tag,[byte]$alg,[byte]$dtype,[byte[]]$digest) 
	{
		$this.KeyTag     = $tag
		$this.Algorithm  = $alg
		$this.DigestType = $dtype
		$this.Digest     = $digest
	}

	static [DnsDsRecord] Parse([byte[]]$rdata) 
	{
		$r       = [DnsBinaryReader]::new($rdata)
		$tagval  = $r.ReadUInt16BE()
		$algVal  = $r.ReadUInt8()
		$dtypeval = $r.ReadUInt8()
		$digval  = $r.ReadBytes($rdata.Length - $r.Position)
		return [DnsDsRecord]::new($tagval,$algVal,$dtypeval,$digval)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.KeyTag)
		$w.WriteUInt8($this.Algorithm)
		$w.WriteUInt8($this.DigestType)
		$w.WriteBytes($this.Digest)
		return $w.ToArray()
	}

	[string] GetDigestHex() 
	{
		return ($this.Digest | ForEach-Object -Process {$_.ToString('x2')}) -join ''
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
	) 
	{
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

	static [DnsRrsigRecord] Parse([DnsBinaryReader]$r, [int]$len) 
	{
		# RDATA begins here
		$startPos = $r.Position

		$typeCval  = $r.ReadUInt16BE()
		$algVal    = $r.ReadUInt8()
		$labelsval = $r.ReadUInt8()
		$origval   = $r.ReadUInt32BE()
		$expval    = $r.ReadUInt32BE()
		$incval    = $r.ReadUInt32BE()
		$tagval    = $r.ReadUInt16BE()

		# SignerName may be compressed Ã¢â€ â€™ must use main reader
		$signerval = $r.ReadName()

		# How many bytes have we consumed so far?
		$bytesConsumed = $r.Position - $startPos

		# Remaining bytes belong to the signature
		$remaining = $len - $bytesConsumed
		if ($remaining -lt 0) 
		{throw "RRSIG parse overran RDLENGTH: consumed $bytesConsumed of $len"}

		$sigval = if ($remaining -gt 0) 
		{$r.ReadBytes($remaining)}
		else 
		{[byte[]]@()}

		return [DnsRrsigRecord]::new(
			$typeCval,$algVal,$labelsval,$origval,$expval,$incval,$tagval,$signerval,$sigval
		)
	}


	[byte[]]ToWireHeaderAndName() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.TypeCovered)
		$w.WriteUInt8($this.Algorithm)
		$w.WriteUInt8($this.Labels)
		$w.WriteUInt32BE($this.OriginalTtl)
		$w.WriteUInt32BE($this.Expiration)
		$w.WriteUInt32BE($this.Inception)
		$w.WriteUInt16BE($this.KeyTag)
		$w.WriteBytes( [byte[]](Get-DnssecCanonicalNameWire -name $this.SignerName) )
		return $w.ToArray()
	}
}
class DnsNsecRecord {
	[string] $NextDomainName
	[int[]]  $Types

	DnsNsecRecord([string]$next,[int[]]$types) 
	{
		$this.NextDomainName = $next
		$this.Types          = $types
	}

	static [string] ReadUncompressedName([DnsBinaryReader]$r) 
	{
		$labels = New-Object -TypeName System.Collections.Generic.List[string]

		while ($true) 
		{
			$len = $r.ReadUInt8()
			if ($len -eq 0) 
			{break}

			$labelBytes = $r.ReadBytes($len)
			$labels.Add([System.Text.Encoding]::ASCII.GetString($labelBytes))
		}

		return ($labels -join '.')
	}

	static [DnsNsecRecord] Parse([byte[]]$rdata) 
	{
		$r        = [DnsBinaryReader]::new($rdata)
		$nextval = ([DnsNsecRecord]::ReadUncompressedName($r)).ToLowerInvariant()
		$typesval = New-Object -TypeName System.Collections.Generic.List[int]

		while ($r.Position -lt $r.Buffer.Length) 
		{
			$blockval = $r.ReadUInt8()
			$lenval   = $r.ReadUInt8()

			if ($lenval -lt 1 -or $lenval -gt 32) 
			{throw "Invalid NSEC bitmap length: $lenval"}

			$bitsval  = $r.ReadBytes($lenval)

			for ($b = 0; $b -lt $bitsval.Length; $b++) 
			{
				for ($bit = 0; $bit -lt 8; $bit++) 
				{
					if ($bitsval[$b] -band (1 -shl (7-$bit))) 
					{$null = $typesval.Add($blockval * 256 + $b*8 + $bit)}
				}
			}
		}

		return [DnsNsecRecord]::new($nextval, $typesval.ToArray())
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.NextDomainName)

		$byBlock = @{}
		foreach ($t in $this.Types) 
		{
			$block  = [int]([math]::Floor($t / 256))
			$offset = $t % 256
			if (-not $byBlock.ContainsKey($block)) 
			{$byBlock[$block] = New-Object -TypeName System.Collections.Generic.List[int]}
			$null = $byBlock[$block].Add($offset)
		}

		foreach ($kv in $byBlock.GetEnumerator() | Sort-Object -Property Key) 
		{
			$block   = [byte]$kv.Key
			$offsets = $kv.Value | Sort-Object
			$maxByte = [int]([math]::Floor(($offsets | Measure-Object -Maximum).Maximum / 8))
			$bitmap  = New-Object -TypeName 'byte[]' -ArgumentList ($maxByte+1)

			foreach ($o in $offsets) 
			{
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
	[byte[]]$OwnerHash
	[byte[]]$NextHash
	[int[]] $Types

	DnsNsec3Record(
		[byte]$alg,[byte]$flags,[uint16]$iter,
		[byte[]]$salt,[byte[]]$ownerHash,[byte[]]$nextHash,[int[]]$types
	)
	{
		$this.HashAlgorithm = $alg
		$this.Flags         = $flags
		$this.Iterations    = $iter
		$this.Salt          = $salt
		$this.OwnerHash     = $ownerHash
		$this.NextHash      = $nextHash
		$this.Types         = $types
	}

	static [DnsNsec3Record] Parse([byte[]]$rdata, [byte[]]$ownerHash)
	{
		$r          = [DnsBinaryReader]::new($rdata)
		$algVal     = $r.ReadUInt8()
		$flagsval   = $r.ReadUInt8()
		$iterval    = $r.ReadUInt16BE()
		$saltLenval = $r.ReadUInt8()
		$saltval    = if ($saltLenval -gt 0) 
		{$r.ReadBytes($saltLenval)}
		else 
		{[byte[]]@()}

		$hashLenval  = $r.ReadUInt8()
		$nextHashval = $r.ReadBytes($hashLenval)

		$typesval = New-Object -TypeName System.Collections.Generic.List[int]
		while ($r.Position -lt $r.Buffer.Length) 
		{
			$blockval = $r.ReadUInt8()
			$lenval   = $r.ReadUInt8()
			if ($lenval -lt 1 -or $lenval -gt 32) 
			{throw "Invalid NSEC3 bitmap length: $lenval"}
			$bitsval  = $r.ReadBytes($lenval)
			for ($b = 0; $b -lt $bitsval.Length; $b++) 
			{
				for ($bit = 0; $bit -lt 8; $bit++) 
				{
					if ($bitsval[$b] -band (1 -shl (7-$bit))) 
					{$null = $typesval.Add($blockval * 256 + $b*8 + $bit)}
				}
			}
		}

		return [DnsNsec3Record]::new(
			$algVal,$flagsval,$iterval,$saltval,
			$ownerHash,          # <-- NEW
			$nextHashval,
			$typesval.ToArray()
		)
	}
    
	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.HashAlgorithm)
		$w.WriteUInt8($this.Flags)
		$w.WriteUInt16BE($this.Iterations)

		if ($this.Salt -and $this.Salt.Length -gt 0) 
		{
			$w.WriteUInt8([byte]$this.Salt.Length)
			$w.WriteBytes($this.Salt)
		}
		else 
		{$w.WriteUInt8(0)}

		$w.WriteUInt8([byte]$this.NextHash.Length)
		$w.WriteBytes($this.NextHash)

		$byBlock = @{}
		foreach ($t in $this.Types) 
		{
			$block  = [int]([math]::Floor($t / 256))
			$offset = $t % 256
			if (-not $byBlock.ContainsKey($block)) 
			{$byBlock[$block] = New-Object -TypeName System.Collections.Generic.List[int]}
			$null = $byBlock[$block].Add($offset)
		}

		foreach ($kv in $byBlock.GetEnumerator() | Sort-Object -Property Key) 
		{
			$block   = [byte]$kv.Key
			$offsets = $kv.Value | Sort-Object
			$maxByte = [int]([math]::Floor(($offsets | Measure-Object -Maximum).Maximum / 8))
			$bitmap  = New-Object -TypeName 'byte[]' -ArgumentList ($maxByte+1)

			foreach ($o in $offsets) 
			{
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
	) 
	{
		$this.Name        = $name
		$this.Type        = $type
		$this.Class       = $class
		$this.Ttl         = $ttl
		$this.RawRData    = $raw
		$this.RDataObject = $obj
	}

	static [DnsResourceRecord] Parse([DnsBinaryReader]$r) 
	{
		$nameValue     = $r.ReadName()
		$typeValue     = $r.ReadUInt16BE()
		$classValue    = $r.ReadUInt16BE()
		$ttlValue      = $r.ReadUInt32BE()
		$rdlengthValue = $r.ReadUInt16BE()
		# Save the position 
		$start = $r.Position
		$objValue = [DnsResourceRecord]::ParseRDataTyped($typeValue, $r, $rdlengthValue)
		$r.Position = $start + $rdlengthValue
		$rdataValue = $r.Buffer[$start..($start + $rdlengthValue - 1)]

		return [DnsResourceRecord]::new(
			$nameValue,
			$typeValue,
			$classValue,
			$ttlValue,
			$rdataValue,
			$objValue
		)
	}

	static [object] ParseRDataTyped([uint16]$type, [DnsBinaryReader]$r, [int]$len) 
	{
		switch ($type) {
			1  
			{return [DnsARecord]::Parse($r, $len)}
			28 
			{return [DnsAaaaRecord]::Parse($r, $len)}
			5  
			{return [DnsCnameRecord]::Parse($r, $len)}
			15 
			{return [DnsMxRecord]::Parse($r, $len)}
			16 
			{return [DnsTxtRecord]::Parse($r, $len)}
			33 
			{return [DnsSrvRecord]::Parse($r, $len)}
			48 
			{return [DnsDnskeyRecord]::Parse($r, $len)}
			43 
			{return [DnsDsRecord]::Parse($r, $len)}
			46 
			{return [DnsRrsigRecord]::Parse($r, $len)}
			47 
			{return [DnsNsecRecord]::Parse($r, $len)}
			50 
			{return [DnsNsec3Record]::Parse($r, $len)}
			default 
			{return $null}
		}
		return $null
	}

	[void] Write([DnsBinaryWriter]$w) 
	{
		$w.WriteName($this.Name)
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
		$w.WriteUInt32BE($this.Ttl)
		$w.WriteUInt16BE([uint16]$this.RawRData.Length)
		$w.WriteBytes($this.RawRData)
	}

	[byte[]] ToCanonicalWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteBytes( [byte[]](Get-DnssecCanonicalNameWire -name $this.Name) )
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
		$w.WriteUInt32BE($this.Ttl)
		$w.WriteUInt16BE([uint16]$this.RawRData.Length)
		$w.WriteBytes($this.RawRData)
		return $w.ToArray()
	}
}
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
	) 
	{
		$this.UdpPayloadSize = $udp
		$this.ExtendedRcode  = $rcode
		$this.Version        = $ver
		$this.Flags          = $flags
		$this.Options        = $opts
	}

	static [DnsOptRecord] Parse([DnsBinaryReader]$r) 
	{
		$name = $r.ReadUInt8()
		if ($name -ne 0) 
		{throw 'Invalid OPT NAME (must be root)'}

		$type = $r.ReadUInt16BE()
		if ($type -ne 41) 
		{throw 'Invalid OPT TYPE'}

		$udpSizeval  = $r.ReadUInt16BE()
		$extRcodeval = $r.ReadUInt8()
		$versionval  = $r.ReadUInt8()
		$flagsval    = $r.ReadUInt16BE()
		$rdlenval    = $r.ReadUInt16BE()
		$optsval     = if ($rdlenval -gt 0) 
		{$r.ReadBytes($rdlenval)}
		else 
		{@()}

		return [DnsOptRecord]::new(
			$udpSizeval, $extRcodeval, $versionval, $flagsval, $optsval
		)
	}

	[void]Write([DnsBinaryWriter]$w) 
	{
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
class DnsPacket {
	[DnsHeader] $Header
	[System.Collections.Generic.List[DnsQuestion]] $Questions
	[System.Collections.Generic.List[DnsResourceRecord]] $Answers
	[System.Collections.Generic.List[DnsResourceRecord]] $Authority
	[System.Collections.Generic.List[DnsResourceRecord]] $Additional
	[DnsOptRecord] $Opt

	DnsPacket() 
	{
		$this.Questions  = [System.Collections.Generic.List[DnsQuestion]]::new()
		$this.Answers    = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Authority  = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Additional = [System.Collections.Generic.List[DnsResourceRecord]]::new()
		$this.Opt        = $null
	}

	static [DnsPacket] Parse([byte[]]$packetBytes) 
	{
		$r = [DnsBinaryReader]::new($packetBytes)
		$pktval = [DnsPacket]::new()
		$pktval.Header = [DnsHeader]::Parse($r)

		for ($i = 0; $i -lt $pktval.Header.QdCount; $i++) 
		{$null = $pktval.Questions.Add([DnsQuestion]::Parse($r))}

		for ($i = 0; $i -lt $pktval.Header.AnCount; $i++) 
		{
			if ($r.Position -ge $r.Buffer.Length) 
			{throw 'DNS header ANCOUNT exceeds packet length'}
			$null = $pktval.Answers.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pktval.Header.NsCount; $i++) 
		{
			if ($r.Position -ge $r.Buffer.Length) 
			{throw 'DNS header NSCOUNT exceeds packet length'}
			$null = $pktval.Authority.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pktval.Header.ArCount; $i++) 
		{
			$saved = $r.Position
			$r.ReadName()
			$type = $r.ReadUInt16BE()
			$r.Position = $saved

			if ($type -eq 41) 
			{
				if ($pktval.Opt) 
				{throw 'Multiple OPT records not allowed'}
				$pktval.Opt = [DnsOptRecord]::Parse($r)
			}
			else 
			{$null = $pktval.Additional.Add([DnsResourceRecord]::Parse($r))}
		}

		return $pktval
	}

	[byte[]] ToArray() 
	{
		$w = [DnsBinaryWriter]::new()

		$optCount = if ($this.Opt) 
		{1}
		else 
		{0}
		$this.Header.ArCount = $this.Additional.Count + $optCount

		$this.Header.Write($w)

		foreach ($q in $this.Questions)  
		{$q.Write($w)}
		foreach ($rr in $this.Answers)   
		{$rr.Write($w)}
		foreach ($rr in $this.Authority) 
		{$rr.Write($w)}
		foreach ($rr in $this.Additional)
		{$rr.Write($w)}

		if ($this.Opt) 
		{$this.Opt.Write($w)}

		return $w.ToArray()
	}
}
class DnsDotClient {
	[string] $Server
	[int]    $Port

	DnsDotClient([string]$server, [int]$port = 853) 
	{
		$this.Server = $server
		$this.Port   = $port
	}

	[DnsPacket] Query([DnsPacket]$packet) 
	{
		$bytes = ConvertTo-DnsWireBytes -packet $packet

		$respBytes = Invoke-DnsTransportSafe -Context 'DoT query' -Operation {
			$tcp = New-Object -TypeName System.Net.Sockets.TcpClient
			$tcp.Connect($this.Server, $this.Port)

			$ssl = New-Object -TypeName System.Net.Security.SslStream -ArgumentList (
				$tcp.GetStream(), 
				$false, 
				{param($s, $c, $ch, $e) return $true}
			)
			$ssl.AuthenticateAsClient($this.Server)

			$lenBytes = [BitConverter]::GetBytes([uint16]$bytes.Length)
			if ([BitConverter]::IsLittleEndian) 
			{[Array]::Reverse($lenBytes)}

			$ssl.Write($lenBytes, 0, 2)
			$ssl.Write($bytes, 0, $bytes.Length)
			$ssl.Flush()

			$lenBuf = New-Object -TypeName byte[] -ArgumentList 2
			$null = $ssl.Read($lenBuf, 0, 2)
			if ([BitConverter]::IsLittleEndian) 
			{[Array]::Reverse($lenBuf)}
			$respLen = [BitConverter]::ToUInt16($lenBuf, 0)

			$resp = New-Object -TypeName byte[] -ArgumentList $respLen
			$read = 0
			while ($read -lt $respLen) 
			{$read += $ssl.Read($resp, $read, $respLen - $read)}

			$ssl.Close()
			$tcp.Close()

			return $resp
		}

		return ConvertFrom-DnsWireBytes -bytes $respBytes
	}
}
class DnsDohClient {
	[string] $Endpoint

	DnsDohClient([string]$endpoint) 
	{$this.Endpoint = $endpoint}

	[DnsPacket] Query([DnsPacket]$packet) 
	{
		$bytes = ConvertTo-DnsWireBytes -packet $packet

		$respBytes = Invoke-DnsTransportSafe -Context 'DoH query' -Operation {
			$client = New-Object -TypeName System.Net.Http.HttpClient
			$content = New-Object -TypeName System.Net.Http.ByteArrayContent -ArgumentList ($bytes)
			$content.Headers.ContentType = 'application/dns-message'

			$response = $client.PostAsync($this.Endpoint, $content).Result
			if (-not $response.IsSuccessStatusCode) 
			{throw "HTTP $($response.StatusCode)"}

			return $response.Content.ReadAsByteArrayAsync().Result
		}

		return ConvertFrom-DnsWireBytes -bytes $respBytes
	}
}

# ============================================================
# Module paths / identity
# ============================================================

$ModuleScriptRoot = $PSScriptRoot
$ModuleName       = (Split-Path -Path (Split-Path -Path $ModuleScriptRoot -Parent) -Leaf)
$PSD1Path         = Join-Path -Path $ModuleScriptRoot -ChildPath ('{0}.psd1' -f $ModuleName)

# ============================================================
# 1. Support functions
# ============================================================

function Get-Psd1Data {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.DesiredStateConfiguration.ArgumentToConfigurationDataTransformation()]
        [Hashtable] $PathToPsd1file
    )
    $PathToPsd1file
}

function Initialize-Folders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Array] $Folders
    )

    foreach ($Item in $Folders) {
        $Path = Join-Path -Path $ModuleScriptRoot -ChildPath $Item
        if (-not (Test-Path -Path $Path)) {
            $null = New-Item -Path $Path -ItemType Directory
        }
    }
}

function Publish-MyEnvironment {
    [CmdletBinding()]
    param(
        [String] $Option = $null
    )

    return  # keeping your original short-circuit

    if ($MyVariables = Get-ChildItem -Path (Join-Path $ModuleScriptRoot -ChildPath ('Functions{0}\Define-Variables*.ps1' -f $Option)) -ErrorAction Ignore) {
        foreach ($Item in ($MyVariables.FullName | Sort-Object)) { . $Item }
    }

    if ($MyCustomXML = Get-ChildItem -Path (Join-Path $ModuleScriptRoot -ChildPath ('Functions{0}\Define-CustomXML.ps1' -f $Option)) -ErrorAction Ignore) {
        foreach ($Item in ($MyCustomXML.FullName | Sort-Object)) { . $Item }
    }
}

function Publish-CustomXML {
    foreach ($Item in ($MyCustomXML.GetEnumerator() | Sort-Object -Property key).Name) {
        $XMLItem = Join-Path -Path $ModuleScriptRoot -ChildPath ('Functions{0}\{1}' -f $Option, $MyCustomXML[$Item].file)
        if (Test-Path -Path $XMLItem) {
            switch ($MyCustomXML[$Item].Action) {
                'Update-FormatData' {
                    switch ($MyCustomXML[$Item].Option) {
                        'Prependpath' { Update-FormatData -PrependPath $XMLItem -ErrorAction Stop }
                        'Appendpath'  { Update-FormatData -AppendPath  $XMLItem -ErrorAction Stop }
                    }
                }
                default {
                    "Unknown item in `$MyCustomXML: [$Item] Option: [$($MyCustomXML[$Item].Option)]" | Write-Warning
                }
            }
        }
    }
}

function Publish-Variables {
    try {
        foreach ($VarSet in ($MyVars.GetEnumerator() | Sort-Object -Property key).Name) {
            foreach ($Item in ($MyVars[$VarSet].GetEnumerator() | Sort-Object -Property key).Name) {
                $Params = @{
                    Name   = $Item
                    Value  = $MyVars[$VarSet][$Item].Value
                    Option = $MyVars[$VarSet][$Item].Option
                    Scope  = $MyVars[$VarSet][$Item].Scope
                }

                New-Variable @Params -ErrorAction Stop
                Export-ModuleMember -Variable $Item -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "Variable [$Item] failed to create"
    }
}

# ============================================================
# 2. MAIN MODULE INITIALIZATION
# ============================================================

try {
	Initialize-Folders -Folders @(
		'Classes\BinaryInfrastructure',
		'Classes\Core',
		'Classes\Basic',
		'Classes\DNSSEC',
		'Classes\Resource',
		'Classes\EDNS-OPT',
		'Classes\DNS',
		'Classes\Transport',
		'Helpers',
		'Functions',
		'FunctionsLinux',
		'FunctionsWindows',
		'FunctionsMacOS'
	)

	$PSD1Data = Get-Psd1Data -PathToPsd1file ('{0}' -f $PSD1Path)

	Publish-MyEnvironment

	# Load common functions
	$Exclude = @('Define-CustomXML|Define-Variables|\.zip$')
	$CommonFunctions = Get-ChildItem -Path (Join-Path $ModuleScriptRoot -ChildPath 'Functions\*.ps1') |
	Where-Object { $_.Name -inotmatch $Exclude }

	foreach ($Item in $CommonFunctions) {
		. $Item.FullName
		#Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
	}

	# OS-specific functions
	switch ($true) {

		($IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) {
			Publish-MyEnvironment -Option 'Windows'
			$WinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsWindows\*.ps1') |
			Where-Object { $_.Name -inotmatch $Exclude }

			foreach ($Item in $WinFunctions) {
				. $Item.FullName
				#Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
			}
		}

		$IsLinux {
			Publish-MyEnvironment -Option 'Linux'
			$LinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsLinux\*.ps1') |
			Where-Object { $_.Name -inotmatch $Exclude }

			foreach ($Item in $LinFunctions) {
				. $Item.FullName
				#Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
			}
		}

		$IsMacOS {
			Publish-MyEnvironment -Option 'MacOS'
			$MacFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsMacOS\*.ps1') |
			Where-Object { $_.Name -inotmatch $Exclude }

			foreach ($Item in $MacFunctions) {
				. $Item.FullName
				#Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
			}
		}
		default {
			throw 'Operating System Unknown'
		}
	}
	$PublicFunctions = @(
		'Add-DnssecTrustAnchor'
		'ConvertFrom-DnsWireBytes'
		'ConvertTo-DnsWireBytes'
		'ConvertTo-HexString'
		'Format-DnssecResult'
		'Get-DnssecCanonicalNameWire'
		'Get-DnssecCanonicalRrsetData'
		'Get-DnssecCanonicalRrWire'
		'Get-DnssecKeyDigest'
		'Get-DnssecKeyDigestHex'
		'Get-DnssecNsec3Hash'
		'Get-DnssecSignedData'
		'Get-DnssecSigningKey'
		'Get-DnssecTrustAnchors'
		'Import-DnssecTrustAnchors'
		'Initialize-DnssecTrustAnchors'
		'Invoke-DnsUdpQuery'
		'New-DnsQueryPacket'
		'Resolve-DnsIterative'
		'Resolve-Dnssec'
		'Resolve-DnssecChain'
		'Resolve-DnssecName'
		'Resolve-NameserverAddress'
		'Test-DnssecAnchoredDnskey'
		'Test-DnssecChain'
		'Test-DnssecDsForDnskey'
		'Test-DnssecName'
		'Test-DnssecNsec3Nodata'
		'Test-DnssecNsec3Nxdomain'
		'Test-DnssecNsec3OptOut'
		'Test-DnssecRrsig'
		'Test-DnssecSignature'
		'Test-DnssecTimeWindow'
	)
	Export-ModuleMember -Function $PublicFunctions #-Alias @() -Variable @()
}
catch {
		Write-Warning "Module initialization failed: $($_.Exception.Message)"
		throw "Unable to initialise module: $ModuleName"
}
