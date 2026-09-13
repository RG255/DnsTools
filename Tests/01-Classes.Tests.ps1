using module dnstools

Describe "Class Loading" {

	It "Loads all core classes" {
		$classes = @(
			# Binary infrastructure
			"DnsBinaryReader","DnsBinaryWriter",

			# Core DNS structures
			"DnsHeader","DnsQuestion",

			# Basic RR types
			"DnsARecord","DnsAaaaRecord","DnsCnameRecord","DnsMxRecord",
			"DnsTxtRecord","DnsSrvRecord","DnsNsRecord","DnsPtrRecord",
			"DnsSoaRecord","DnsCaaRecord","DnsDnameRecord",
			"DnsNaptrRecord","DnsSshfpRecord","DnsTlsaRecord","DnsUriRecord",

			# DNSSEC
			"DnsDnskeyRecord","DnsDsRecord","DnsRrsigRecord",
			"DnsNsecRecord","DnsNsec3Record",

			# Resource & EDNS
			"DnsResourceRecord","DnsOptRecord",

			# DNS packet
			"DnsPacket",

			# Transport
			"DnsDotClient","DnsDohClient"
		)

		foreach ($c in $classes) {
			$type = [AppDomain]::CurrentDomain.GetAssemblies() |
				ForEach-Object { $_.GetTypes() } |
				Where-Object { $_.Name -eq $c } |
				Select-Object -First 1

			$type | Should -Not -BeNullOrEmpty
		}
	}
}
