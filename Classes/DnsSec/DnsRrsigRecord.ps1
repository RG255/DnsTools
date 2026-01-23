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

		# SignerName may be compressed â†’ must use main reader
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