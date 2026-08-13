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
