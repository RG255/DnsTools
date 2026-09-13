using module dnstools

Describe "Edge Cases" {

	It "Handles empty packets" {
		{ ConvertFrom-DnsPacket -Packet @() } | Should -Throw
	}

	It "Handles malformed RDLENGTH" {
		$bad = [byte[]](0,0,0,0,0,0,0,1,0,1,0,1,0,0,255) # too short
		{ ConvertFrom-DnsPacket -Packet $bad } | Should -Throw
	}

	It "Handles unknown RR types" {
		$rr = [DnsResourceRecord]::new("x", 9999, 1, 0, @(1,2,3), $null)
		$rr.RDataObject | Should -BeNullOrEmpty
	}
}
