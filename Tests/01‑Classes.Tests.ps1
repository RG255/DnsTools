using module dnstools

Describe "Class Loading" {

    It "Loads all core classes" {
        $classes = @(
            "DnsBinaryReader","DnsBinaryWriter",
            "DnsHeader","DnsQuestion",
            "DnsARecord","DnsAaaaRecord","DnsTxtRecord",
            "DnsCnameRecord","DnsMxRecord","DnsSrvRecord","DnsNsRecord",
            "DnsDnskeyRecord","DnsDsRecord","DnsRrsigRecord",
            "DnsNsecRecord","DnsNsec3Record",
            "DnsResourceRecord","DnsOptRecord","DnsPacket"
        )

        foreach ($c in $classes) {
            $type = [System.Management.Automation.LanguagePrimitives]::ConvertTo($c, [type], $null)
            $type | Should -Not -BeNullOrEmpty
        }
    }
}
