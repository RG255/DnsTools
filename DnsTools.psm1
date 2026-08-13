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
	static [DnsARecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$bytes = $r.ReadBytes($len)
		return [DnsARecord]@{
			Address = ([System.Net.IPAddress]::new($bytes)).ToString()
		}
	}
}
class DnsAaaaRecord {
	[string]$Address
	static [DnsAaaaRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$bytes = $r.ReadBytes($len)
		return [DnsAaaaRecord]@{
			Address = ([System.Net.IPAddress]::new($bytes)).ToString()
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
		$pref = $r.ReadUInt16BE()
		$exch = $r.ReadName()
		return [DnsMxRecord]::new($pref, $exch)
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
		$pri  = $r.ReadUInt16BE()
		$wgt  = $r.ReadUInt16BE()
		$prt = $r.ReadUInt16BE()
		$tgt  = $r.ReadName()
		return [DnsSrvRecord]::new($pri,$wgt,$prt,$tgt)
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
class DnsPtrRecord {
    [string]$Pointer

    DnsPtrRecord([string]$pointer) {
        $this.Pointer = $pointer
    }

    static [DnsPtrRecord] Parse([DnsBinaryReader]$r, [int]$len) {
        $name = $r.ReadName()
        return [DnsPtrRecord]::new($name)
    }

    [byte[]]ToWire() {
        $w = [DnsBinaryWriter]::new()
        $w.WriteName($this.Pointer)
        return $w.ToArray()
    }
}
class DnsSoaRecord {
	[string]$MName      # Primary nameserver
	[string]$RName      # Responsible person email (@ replaced with .)
	[uint32]$Serial     # Zone serial number
	[uint32]$Refresh    # Seconds between zone refreshes
	[uint32]$Retry      # Seconds between retry attempts
	[uint32]$Expire     # Seconds until zone is no longer authoritative
	[uint32]$Minimum    # Minimum TTL for negative caching

	DnsSoaRecord(
		[string]$mname,
		[string]$rname,
		[uint32]$serial,
		[uint32]$refresh,
		[uint32]$retry,
		[uint32]$expire,
		[uint32]$minimum
	)
	{
		$this.MName   = $mname
		$this.RName   = $rname
		$this.Serial  = $serial
		$this.Refresh = $refresh
		$this.Retry   = $retry
		$this.Expire  = $expire
		$this.Minimum = $minimum
	}

	static [DnsSoaRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$mn   = $r.ReadName()
		$rn   = $r.ReadName()
		$ser  = $r.ReadUInt32BE()
		$rfr = $r.ReadUInt32BE()
		$rty   = $r.ReadUInt32BE()
		$xpr  = $r.ReadUInt32BE()
		$min = $r.ReadUInt32BE()

		return [DnsSoaRecord]::new(
			$mn, $rn, $ser,
			$rfr, $rty, $xpr, $min
		)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.MName)
		$w.WriteName($this.RName)
		$w.WriteUInt32BE($this.Serial)
		$w.WriteUInt32BE($this.Refresh)
		$w.WriteUInt32BE($this.Retry)
		$w.WriteUInt32BE($this.Expire)
		$w.WriteUInt32BE($this.Minimum)
		return $w.ToArray()
	}
}
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
class DnsDnameRecord {
	[string]$Target

	DnsDnameRecord([string]$target)
	{
		$this.Target = $target
	}

	static [DnsDnameRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$name = $r.ReadName()
		return [DnsDnameRecord]::new($name)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.Target)
		return $w.ToArray()
	}
}
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
class DnsSshfpRecord {
	[byte]$Algorithm          # 1=RSA, 2=DSS, 3=ECDSA, 4=Ed25519
	[byte]$FingerprintType    # 1=SHA-1, 2=SHA-256
	[byte[]]$Fingerprint      # Public key fingerprint

	DnsSshfpRecord([byte]$alg, [byte]$fpType, [byte[]]$fp)
	{
		$this.Algorithm = $alg
		$this.FingerprintType = $fpType
		$this.Fingerprint = $fp
	}

	static [DnsSshfpRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$alg = $r.ReadUInt8()
		$fpt = $r.ReadUInt8()
		$remaining = $len - ($r.Position - $startPos)
		$fp = $r.ReadBytes($remaining)

		return [DnsSshfpRecord]::new($alg, $fpt, $fp)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.Algorithm)
		$w.WriteUInt8($this.FingerprintType)
		$w.WriteBytes($this.Fingerprint)
		return $w.ToArray()
	}

	[string]GetFingerprintHex()
	{
		return ($this.Fingerprint | ForEach-Object { $_.ToString('x2') }) -join ''
	}
}
class DnsTlsaRecord {
	[byte]$CertUsage           # 0-3: PKIX-TA, PKIX-EE, DANE-TA, DANE-EE
	[byte]$Selector            # 0=Full cert, 1=SubjectPublicKeyInfo
	[byte]$MatchingType        # 0=Full, 1=SHA-256, 2=SHA-512
	[byte[]]$CertificateData   # Certificate association data

	DnsTlsaRecord([byte]$usage, [byte]$sel, [byte]$matching, [byte[]]$data)
	{
		$this.CertUsage = $usage
		$this.Selector = $sel
		$this.MatchingType = $matching
		$this.CertificateData = $data
	}

	static [DnsTlsaRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$usage = $r.ReadUInt8()
		$sel = $r.ReadUInt8()
		$mtch = $r.ReadUInt8()
		$remaining = $len - ($r.Position - $startPos)
		$data = $r.ReadBytes($remaining)

		return [DnsTlsaRecord]::new($usage, $sel, $mtch, $data)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.CertUsage)
		$w.WriteUInt8($this.Selector)
		$w.WriteUInt8($this.MatchingType)
		$w.WriteBytes($this.CertificateData)
		return $w.ToArray()
	}
}
class DnsRpRecord {
	[string]$MailBox      # Responsible person's mailbox encoded as a domain name (e.g. admin.example.com = admin@example.com)
	[string]$TxtDomain    # Domain name whose TXT records hold further contact information

	DnsRpRecord([string]$mbox, [string]$txt)
	{
		$this.MailBox   = $mbox
		$this.TxtDomain = $txt
	}

	static [DnsRpRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$mbox = $r.ReadName()
		$txt  = $r.ReadName()
		return [DnsRpRecord]::new($mbox, $txt)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.MailBox)
		$w.WriteName($this.TxtDomain)
		return $w.ToArray()
	}
}
class DnsIpsecKeyRecord {
	[byte]  $Precedence    # Like MX preference - lower is preferred
	[byte]  $GatewayType   # 0=none, 1=IPv4, 2=IPv6, 3=domain name
	[byte]  $Algorithm     # 0=none, 1=DSA, 2=RSA, 3=ECDSA
	[string]$Gateway       # Presentation form: '.', an IPv4/IPv6 address, or a domain name
	[byte[]]$PublicKey     # Raw public key (base64 in presentation)

	DnsIpsecKeyRecord([byte]$prec, [byte]$gwType, [byte]$alg, [string]$gw, [byte[]]$key)
	{
		$this.Precedence  = $prec
		$this.GatewayType = $gwType
		$this.Algorithm   = $alg
		$this.Gateway     = $gw
		$this.PublicKey   = $key
	}

	static [DnsIpsecKeyRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$prec   = $r.ReadUInt8()
		$gwType = $r.ReadUInt8()
		$alg    = $r.ReadUInt8()

		$gw = '.'
		switch ($gwType)
		{
			0 {$gw = '.'}
			1 {$gw = ([System.Net.IPAddress]::new($r.ReadBytes(4))).ToString()}
			2 {$gw = ([System.Net.IPAddress]::new($r.ReadBytes(16))).ToString()}
			3 {$gw = $r.ReadName()}
			default {throw "Invalid IPSECKEY gateway type: $gwType"}
		}

		$remaining = $len - ($r.Position - $startPos)
		$key = if ($remaining -gt 0) {$r.ReadBytes($remaining)} else {[byte[]]@()}

		return [DnsIpsecKeyRecord]::new($prec, $gwType, $alg, $gw, $key)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt8($this.Precedence)
		$w.WriteUInt8($this.GatewayType)
		$w.WriteUInt8($this.Algorithm)
		switch ($this.GatewayType)
		{
			0 {}
			1 {$w.WriteBytes([System.Net.IPAddress]::Parse($this.Gateway).GetAddressBytes())}
			2 {$w.WriteBytes([System.Net.IPAddress]::Parse($this.Gateway).GetAddressBytes())}
			3 {$w.WriteName($this.Gateway)}
		}
		if ($this.PublicKey -and $this.PublicKey.Length -gt 0)
		{$w.WriteBytes($this.PublicKey)}
		return $w.ToArray()
	}

	[string]GetPublicKeyBase64()
	{return [Convert]::ToBase64String($this.PublicKey)}
}
class DnsOpenPgpKeyRecord {
	[byte[]]$PublicKey     # OpenPGP transferable public key (raw bytes; base64 in presentation)

	DnsOpenPgpKeyRecord([byte[]]$key)
	{$this.PublicKey = $key}

	static [DnsOpenPgpKeyRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$key = if ($len -gt 0) {$r.ReadBytes($len)} else {[byte[]]@()}
		return [DnsOpenPgpKeyRecord]::new($key)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		if ($this.PublicKey -and $this.PublicKey.Length -gt 0)
		{$w.WriteBytes($this.PublicKey)}
		return $w.ToArray()
	}

	[string]GetPublicKeyBase64()
	{return [Convert]::ToBase64String($this.PublicKey)}
}
class DnsUriRecord {
	[uint16]$Priority
	[uint16]$Weight
	[string]$Target

	DnsUriRecord([uint16]$priority, [uint16]$weight, [string]$target)
	{
		$this.Priority = $priority
		$this.Weight   = $weight
		$this.Target   = $target
	}

	static [DnsUriRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$pri = $r.ReadUInt16BE()
		$wgt = $r.ReadUInt16BE()

		# Target is a character-string (raw bytes, not length-prefixed in URI)
		# Remaining length after priority and weight is len - 4
		$tgtLen = $len - 4
		if ($tgtLen -gt 0) {
			$tgtBytes = $r.ReadBytes($tgtLen)
			$tgt = [System.Text.Encoding]::ASCII.GetString($tgtBytes)
		} else {
			$tgt = ''
		}

		return [DnsUriRecord]::new($pri, $wgt, $tgt)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Priority)
		$w.WriteUInt16BE($this.Weight)
		$bytes = [System.Text.Encoding]::ASCII.GetBytes($this.Target)
		$w.WriteBytes($bytes)
		return $w.ToArray()
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
    
	static [DnsDnskeyRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$flgs = $r.ReadUInt16BE()
		$proto = $r.ReadUInt8()
		$alg   = $r.ReadUInt8()
		$remaining = $len - ($r.Position - $startPos)
		$key   = $r.ReadBytes($remaining)
		return [DnsDnskeyRecord]::new($flgs, $proto, $alg, $key)
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

	static [DnsDsRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$tag  = $r.ReadUInt16BE()
		$alg  = $r.ReadUInt8()
		$dtype = $r.ReadUInt8()
		$remaining = $len - ($r.Position - $startPos)
		$dig  = $r.ReadBytes($remaining)
		return [DnsDsRecord]::new($tag,$alg,$dtype,$dig)
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

		$typeC  = $r.ReadUInt16BE()
		$alg    = $r.ReadUInt8()
		$lbls = $r.ReadUInt8()
		$orig   = $r.ReadUInt32BE()
		$exp    = $r.ReadUInt32BE()
		$inc    = $r.ReadUInt32BE()
		$tag    = $r.ReadUInt16BE()

		# SignerName may be compressed -> must use main reader
		$signer = $r.ReadName()

		# How many bytes have we consumed so far?
		$bytesConsumed = $r.Position - $startPos

		# Remaining bytes belong to the signature
		$remaining = $len - $bytesConsumed
		if ($remaining -lt 0) 
		{throw "RRSIG parse overran RDLENGTH: consumed $bytesConsumed of $len"}

		$sig = if ($remaining -gt 0) 
		{$r.ReadBytes($remaining)}
		else 
		{[byte[]]@()}

		return [DnsRrsigRecord]::new(
			$typeC,$alg,$lbls,$orig,$exp,$inc,$tag,$signer,$sig
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

	static [DnsNsecRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$startPos = $r.Position
		$endPos   = $startPos + $len
		$next = ([DnsNsecRecord]::ReadUncompressedName($r)).ToLowerInvariant()
		$typs = New-Object -TypeName System.Collections.Generic.List[int]

		while ($r.Position -lt $endPos) 
		{
			$block = $r.ReadUInt8()
			$len   = $r.ReadUInt8()

			if ($len -lt 1 -or $len -gt 32) 
			{throw "Invalid NSEC bitmap length: $len"}

			$bits  = $r.ReadBytes($len)

			for ($b = 0; $b -lt $bits.Length; $b++) 
			{
				for ($bit = 0; $bit -lt 8; $bit++) 
				{
					if ($bits[$b] -band (1 -shl (7-$bit))) 
					{$null = $typs.Add($block * 256 + $b*8 + $bit)}
				}
			}
		}

		return [DnsNsecRecord]::new($next, $typs.ToArray())
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
		[byte[]]$salt,[byte[]]$oHash,[byte[]]$nextHash,[int[]]$types
	)
	{
		$this.HashAlgorithm = $alg
		$this.Flags         = $flags
		$this.Iterations    = $iter
		$this.Salt          = $salt
		$this.OwnerHash     = $oHash
		$this.NextHash      = $nextHash
		$this.Types         = $types
	}

	static [byte[]] Base32HexDecode([string]$encoded)
	{
		# RFC 4648 Base32hex alphabet: 0-9, A-V (uppercase)
		$alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV'
		$encoded = $encoded.ToUpper().Replace('=', '')

		if ($encoded.Length -eq 0) { return [byte[]]@() }

		$bits = ''
		foreach ($char in $encoded.ToCharArray())
		{
			$val = $alphabet.IndexOf($char)
			if ($val -eq -1) { throw "Invalid Base32hex character: $char" }
			$bits += [Convert]::ToString($val, 2).PadLeft(5, '0')
		}

		$bytes = [System.Collections.Generic.List[byte]]::new()
		for ($i = 0; $i -lt $bits.Length - 7; $i += 8)
		{
			$byteStr = $bits.Substring($i, 8)
			$bytes.Add([Convert]::ToByte($byteStr, 2))
		}

		return [byte[]]$bytes.ToArray()
	}

	static [DnsNsec3Record] Parse([DnsBinaryReader]$r, [int]$len, [string]$ownerName)
	{
		$startPos   = $r.Position
		$endPos     = $startPos + $len

		# Extract owner hash from base32hex-encoded first label of owner name
		$firstLabel = $ownerName.Split('.')[0].ToUpper()
		$oHash = [DnsNsec3Record]::Base32HexDecode($firstLabel)

		$alg     = $r.ReadUInt8()
		$flgs   = $r.ReadUInt8()
		$iter    = $r.ReadUInt16BE()
		$saltLen = $r.ReadUInt8()
		$slt    = if ($saltLen -gt 0)
		{$r.ReadBytes($saltLen)}
		else
		{[byte[]]@()}

		$hashLen  = $r.ReadUInt8()
		$nxtHash = $r.ReadBytes($hashLen)

		$typs = New-Object -TypeName System.Collections.Generic.List[int]
		while ($r.Position -lt $endPos) 
		{
			$block = $r.ReadUInt8()
			$len   = $r.ReadUInt8()
			if ($len -lt 1 -or $len -gt 32) 
			{throw "Invalid NSEC3 bitmap length: $len"}
			$bits  = $r.ReadBytes($len)
			for ($b = 0; $b -lt $bits.Length; $b++) 
			{
				for ($bit = 0; $bit -lt 8; $bit++) 
				{
					if ($bits[$b] -band (1 -shl (7-$bit))) 
					{$null = $typs.Add($block * 256 + $b*8 + $bit)}
				}
			}
		}

		return [DnsNsec3Record]::new(
			$alg,$flgs,$iter,$slt,
			$oHash,
			$nxtHash,
			$typs.ToArray()
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
		$objValue = [DnsResourceRecord]::ParseRDataTyped($typeValue, $r, $rdlengthValue, $nameValue)
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

	static [object] ParseRDataTyped([uint16]$type, [DnsBinaryReader]$r, [int]$len, [string]$ownerName) 
	{
		switch ($type) {
			1
			{return [DnsARecord]::Parse($r, $len)}
			2
			{return [DnsNsRecord]::Parse($r, $len)}
			28
			{return [DnsAaaaRecord]::Parse($r, $len)}
			5
			{return [DnsCnameRecord]::Parse($r, $len)}
			6
			{return [DnsSoaRecord]::Parse($r, $len)}
			12
			{return [DnsPtrRecord]::Parse($r, $len)}
			15
			{return [DnsMxRecord]::Parse($r, $len)}
			16 
			{return [DnsTxtRecord]::Parse($r, $len)}
			33
			{return [DnsSrvRecord]::Parse($r, $len)}
			35
			{return [DnsNaptrRecord]::Parse($r, $len)}
			39
			{return [DnsDnameRecord]::Parse($r, $len)}
			48
			{return [DnsDnskeyRecord]::Parse($r, $len)}
			43
			{return [DnsDsRecord]::Parse($r, $len)}
			44
			{return [DnsSshfpRecord]::Parse($r, $len)}
			46
			{return [DnsRrsigRecord]::Parse($r, $len)}
			47
			{return [DnsNsecRecord]::Parse($r, $len)}
			50
			{return [DnsNsec3Record]::Parse($r, $len, $ownerName)}
			52
			{return [DnsTlsaRecord]::Parse($r, $len)}
			17
			{return [DnsRpRecord]::Parse($r, $len)}
			45
			{return [DnsIpsecKeyRecord]::Parse($r, $len)}
			61
			{return [DnsOpenPgpKeyRecord]::Parse($r, $len)}
			256
			{return [DnsUriRecord]::Parse($r, $len)}
			257
			{return [DnsCaaRecord]::Parse($r, $len)}
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

		$udp  = $r.ReadUInt16BE()
		$rcode = $r.ReadUInt8()
		$ver  = $r.ReadUInt8()
		$flgs    = $r.ReadUInt16BE()
		$rdlen = $r.ReadUInt16BE()
		[byte[]]$opts = $null
		if ($rdlen -gt 0) {
			$opts = $r.ReadBytes($rdlen)
		} else {
			$opts = [byte[]]@()
		}

		return [DnsOptRecord]::new(
			$udp, $rcode, $ver, $flgs, $opts
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
		$pkt = [DnsPacket]::new()
		$pkt.Header = [DnsHeader]::Parse($r)

		for ($i = 0; $i -lt $pkt.Header.QdCount; $i++) 
		{$null = $pkt.Questions.Add([DnsQuestion]::Parse($r))}

		for ($i = 0; $i -lt $pkt.Header.AnCount; $i++) 
		{
			if ($r.Position -ge $r.Buffer.Length) 
			{throw 'DNS header ANCOUNT exceeds packet length'}
			$null = $pkt.Answers.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pkt.Header.NsCount; $i++) 
		{
			if ($r.Position -ge $r.Buffer.Length) 
			{throw 'DNS header NSCOUNT exceeds packet length'}
			$null = $pkt.Authority.Add([DnsResourceRecord]::Parse($r))
		}

		for ($i = 0; $i -lt $pkt.Header.ArCount; $i++)
		{
			$saved = $r.Position

			# OPT records always have name = root (single 0x00 byte)
			# Check the first byte to determine if this might be an OPT record
			$firstByte = $r.ReadUInt8()
			$r.Position = $saved

			# If first byte is 0x00, peek at the type to confirm it's OPT
			if ($firstByte -eq 0)
			{
				$r.Position = $saved + 1  # Skip the 0x00 name
				$type = $r.ReadUInt16BE()
				$r.Position = $saved

				if ($type -eq 41)
				{
					if ($pkt.Opt)
					{throw 'Multiple OPT records not allowed'}
					$pkt.Opt = [DnsOptRecord]::Parse($r)
					continue
				}
			}

			# Not an OPT record, parse as regular resource record
			$null = $pkt.Additional.Add([DnsResourceRecord]::Parse($r))
		}

		return $pkt
	}

	[byte[]] ToArray()
	{
		$w = [DnsBinaryWriter]::new()

		$optCount = if ($this.Opt) {1} else {0}
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
		$queryBytes = $packet.ToArray()

		try {
			$tcp = New-Object -TypeName System.Net.Sockets.TcpClient
			$tcp.Connect($this.Server, $this.Port)

			$ssl = New-Object -TypeName System.Net.Security.SslStream -ArgumentList (
				$tcp.GetStream(),
				$false,
				{param($s, $c, $ch, $e) return $true}
			)
			$ssl.AuthenticateAsClient($this.Server)

			$lenBytes = [BitConverter]::GetBytes([uint16]$queryBytes.Length)
			if ([BitConverter]::IsLittleEndian)
			{[Array]::Reverse($lenBytes)}

			$ssl.Write($lenBytes, 0, 2)
			$ssl.Write($queryBytes, 0, $queryBytes.Length)
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

			return [DnsPacket]::Parse($resp)
		}
		catch {
			throw "DoT query failed: $($_.Exception.Message)"
		}
	}
}
class DnsDohClient {
	[string] $Endpoint

	DnsDohClient([string]$endpoint) 
	{$this.Endpoint = $endpoint}

	[DnsPacket] Query([DnsPacket]$packet)
	{
		$queryBytes = $packet.ToArray()

		try {
			$httpClient = New-Object -TypeName System.Net.Http.HttpClient
			$content = New-Object -TypeName System.Net.Http.ByteArrayContent -ArgumentList (,$queryBytes)
			$content.Headers.ContentType = 'application/dns-message'

			$response = $httpClient.PostAsync($this.Endpoint, $content).Result
			if (-not $response.IsSuccessStatusCode)
			{throw "HTTP $($response.StatusCode)"}

			$respBytes = $response.Content.ReadAsByteArrayAsync().Result
			return [DnsPacket]::Parse($respBytes)
		}
		catch {
			throw "DoH query failed: $($_.Exception.Message)"
		}
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

function Get-Psd1Data 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[Microsoft.PowerShell.DesiredStateConfiguration.ArgumentToConfigurationDataTransformation()]
		[Hashtable] $PathToPsd1file
	)
	$PathToPsd1file
}

function Initialize-Folders 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[Array] $Folders
	)

	foreach ($Item in $Folders) 
	{
		$Path = Join-Path -Path $ModuleScriptRoot -ChildPath $Item
		if (-not (Test-Path -Path $Path)) 
		{$null = New-Item -Path $Path -ItemType Directory}
	}
}

function Publish-MyEnvironment 
{
	[CmdletBinding()]
	param(
		[String] $Option = $null
	)

	foreach ($Item in ($PSD1Data.PrivateData.ModuleVars[$Option].keys | Sort-Object))
	{
		$FilePath = Join-Path -Path $ModuleScriptRoot -ChildPath ('Functions{0}\{1}' -f $Option, $PSD1Data.PrivateData.ModuleVars[$Option][$Item]) -ErrorAction Stop
		If (Test-Path -Path $FilePath)
		{
			# Dot-source the DefineVariables file to load its variables
			. $FilePath
		}
	}

	if ($MyCustomXML = Get-ChildItem -Path (Join-Path $ModuleScriptRoot -ChildPath ('Functions{0}\Define-CustomXML.ps1' -f $Option)) -ErrorAction Ignore) 
	{
		foreach ($Item in ($MyCustomXML.FullName | Sort-Object)) 
		{. $Item}
	}
}

function Publish-CustomXML 
{
	foreach ($Item in ($MyCustomXML.GetEnumerator() | Sort-Object -Property key).Name) 
	{
		$XMLItem = Join-Path -Path $ModuleScriptRoot -ChildPath ('Functions{0}\{1}' -f $Option, $MyCustomXML[$Item].file)
		if (Test-Path -Path $XMLItem) 
		{
			switch ($MyCustomXML[$Item].Action) {
				'Update-FormatData' 
				{
					switch ($MyCustomXML[$Item].Option) {
						'Prependpath' 
						{Update-FormatData -PrependPath $XMLItem -ErrorAction Stop}
						'Appendpath'  
						{Update-FormatData -AppendPath  $XMLItem -ErrorAction Stop}
					}
				}
				default 
				{"Unknown item in `$MyCustomXML: [$Item] Option: [$($MyCustomXML[$Item].Option)]" | Write-Warning}
			}
		}
	}
}

Function Publish-Variables
{
	<#
			.SYNOPSIS
			Takes the definitions in $Variables and processes them into the variables defined.

			.DESCRIPTION
			As Above

			.EXAMPLE
			Publish-Variables is called from the file Define-Variables.ps1 which is executed as part
			of this psm1 file when the module is initialised.

			.EXAMPLE
			Publish-Variables -Variables $MyVars
	#>
	Param ([hashtable]$Variables)
	Try
	{
		ForEach ($VarSet in ($Variables.GetEnumerator() | Sort-Object -Property key).Name)
		{
			ForEach ($Item in ($Variables[$VarSet].GetEnumerator() | Sort-Object -Property key).Name)
			{
				$Params = @{
					Name   = $null
					Value  = $null
					Option = $null
					Scope  = $null
				}
				If (Test-Path -Path ('Variable:{0}:{1}' -f $Variables[$VarSet][$Item].Scope, $Item))
				{
					$Params = @{
						Name  = $Item
						Scope = $Variables[$VarSet][$Item].Scope
					}
					If ($Params.Scope -inotmatch $VOConstant)
					{Remove-Variable @Params -Force}
				}
				$Params = @{
					Name   = $Item
					Value  = $Variables[$VarSet][$Item].Value
					Option = $Variables[$VarSet][$Item].Option
					Scope  = $Variables[$VarSet][$Item].Scope
				}
				New-Variable @Params -ErrorAction Stop
				Export-ModuleMember -Variable $Item -ErrorAction Stop
				$var = Get-Variable -Name VInfoOn -Scope Local -ErrorAction SilentlyContinue
				if ($var -and $var.Value -is [bool] -and $var.Value) 
				{
					{
						$Msg = 'Variable:[{0}] created Value: [{1}]' -f $Item, $Params.Value
						Write-Information -MessageData $Msg -InformationAction Continue
					}
				}
			}
		}
	}
	Catch
	{
		$Msg = 'Variable:[{0}] Failed to create Value: [{1}]' -f $Item, $Params.Value
		Write-Information -MessageData $Msg -InformationAction Continue
	}
}

# ============================================================
# 2. MAIN MODULE INITIALIZATION
# ============================================================

try 
{
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

	# Root-hints session state (populated by Helpers\Get-RootHints.ps1 during Publish-MyEnvironment;
	# initialised here so it is always defined under Set-StrictMode).
	$script:DnsRootHintsVerified        = $null
	$script:DnsRootHintsBaselineDiffers = $false

	Publish-MyEnvironment

	# Check if we should export all functions (for testing)
	$ExportAll = ($env:DNSTOOLS_EXPORT_ALL -eq '1')

	# Load common functions
	$VarDefFiles = @($PSD1Data.PrivateData.ModuleVars[''].Values)
	$Exclude = @('Define-CustomXML|\.zip$')
	$MyPath = (Join-Path -Path $ModuleScriptRoot -ChildPath ('Functions\*{0}' -f $StrExtPS1) -ErrorAction Stop)
	$CommonFunctions = (Get-ChildItem -Path $MyPath -ErrorAction stop | Where-Object {$_.Name -inotmatch $Exclude -and $_.Name -notin $VarDefFiles} ) |
	Where-Object {$_.Name -inotmatch $Exclude}

	foreach ($Item in $CommonFunctions)
	{
		If ($FInfoOn)
		{
			$Msg = 'Processing Function:[{0}]' -f $Item.FullName
			Write-Information -MessageData $Msg -InformationAction Continue
		}
		. $Item.FullName
		if (-not (Get-Command $Item.BaseName -CommandType Function -ErrorAction SilentlyContinue))
		{Write-Host "Function [$($Item.BaseName)] was NOT created by file [$($Item.Name)]"}
		else
		{
			$funcName = $Item.BaseName
			# Export all if env var set, otherwise check export table
			$shouldExport = $ExportAll -or $true  # Default to export if not in table
			if (-not $ExportAll -and $script:FunctionExportTable -and $script:FunctionExportTable.ContainsKey($funcName)) 
			{$shouldExport = $script:FunctionExportTable[$funcName]}
			if ($shouldExport) 
			{Export-ModuleMember -Function $funcName -ErrorAction Stop}
		}
	}

	# OS-specific functions 2=Windows 4=Linux 6=MacOS
	switch ([System.Environment]::OSVersion.Platform.value__) {
		2
		{
			Publish-MyEnvironment -Option 'Windows'
			$VarDefFiles = @($PSD1Data.PrivateData.ModuleVars['Windows'].Values)
			$Exclude = @('Define-CustomXML|{0}$' -f $StrExtZip)
			$WinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsWindows\*.ps1') |
			Where-Object {$_.Name -inotmatch $Exclude -and $_.Name -notin $VarDefFiles}

			foreach ($Item in $WinFunctions)
			{
				If ($FInfoOn)
				{
					$Msg = 'Processing Function:[{0}]' -f $Item.FullName
					Write-Information -MessageData $Msg -InformationAction Continue
				}
				. $Item.FullName
				if (-not (Get-Command $Item.BaseName -CommandType Function -ErrorAction SilentlyContinue))
				{Write-Host "Function [$($Item.BaseName)] was NOT created by file [$($Item.Name)]"}
				else
				{
					$funcName = $Item.BaseName
					$shouldExport = $ExportAll -or $true
					if (-not $ExportAll -and $script:FunctionExportTable -and $script:FunctionExportTable.ContainsKey($funcName)) 
					{$shouldExport = $script:FunctionExportTable[$funcName]}
					if ($shouldExport) 
					{Export-ModuleMember -Function $funcName -ErrorAction Stop}
				}
			}
		}
		4
		{
			Publish-MyEnvironment -Option 'Linux'
			$LinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsLinux\*.ps1') |
			Where-Object {$_.Name -inotmatch $Exclude}

			foreach ($Item in $LinFunctions)
			{
				If ($FInfoOn)
				{
					$Msg = 'Processing Function:[{0}]' -f $Item.FullName
					Write-Information -MessageData $Msg -InformationAction Continue
				}
				. $Item.FullName
				if (-not (Get-Command $Item.BaseName -CommandType Function -ErrorAction SilentlyContinue))
				{Write-Host "Function [$($Item.BaseName)] was NOT created by file [$($Item.Name)]"}
				else
				{
					$funcName = $Item.BaseName
					$shouldExport = $ExportAll -or $true
					if (-not $ExportAll -and $script:FunctionExportTable -and $script:FunctionExportTable.ContainsKey($funcName)) 
					{$shouldExport = $script:FunctionExportTable[$funcName]}
					if ($shouldExport) 
					{Export-ModuleMember -Function $funcName -ErrorAction Stop}
				}
			}
		}
		6
		{
			Publish-MyEnvironment -Option 'MacOS'
			$MacFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsMacOS\*.ps1') |
			Where-Object {$_.Name -inotmatch $Exclude}

			foreach ($Item in $MacFunctions)
			{
				If ($FInfoOn)
				{
					$Msg = 'Processing Function:[{0}]' -f $Item.FullName
					Write-Information -MessageData $Msg -InformationAction Continue
				}
				. $Item.FullName
				if (-not (Get-Command $Item.BaseName -CommandType Function -ErrorAction SilentlyContinue))
				{Write-Host "Function [$($Item.BaseName)] was NOT created by file [$($Item.Name)]"}
				else
				{
					$funcName = $Item.BaseName
					$shouldExport = $ExportAll -or $true
					if (-not $ExportAll -and $script:FunctionExportTable -and $script:FunctionExportTable.ContainsKey($funcName)) 
					{$shouldExport = $script:FunctionExportTable[$funcName]}
					if ($shouldExport) 
					{Export-ModuleMember -Function $funcName -ErrorAction Stop}
				}
			}
		}
		default
		{throw 'Operating System Unknown'}
	}

	# Root hints: if the verified set loaded at import differs from the trusted baseline, briefly offer to
	# persist it. Fully isolated - a prompt or elevation failure must never break module import.
	try
	{Invoke-RootHintsBaselineOffer}
	catch
	{Write-Verbose -Message ('Root-hints baseline offer skipped: {0}' -f $_.Exception.Message)}
}
catch
{
	Write-Warning "Module initialization failed: $($_.Exception.Message)"
	throw "Unable to initialise module: $ModuleName"
}
