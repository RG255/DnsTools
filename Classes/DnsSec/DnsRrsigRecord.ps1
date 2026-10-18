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

		# Typed statement-form assignment: an if-expression result is unrolled and an empty array becomes $null.
		[byte[]]$sig = $r.ReadBytes($remaining)

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