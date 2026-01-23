using module '..\DnsTools.psm1'

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
            $type = [AppDomain]::CurrentDomain.GetAssemblies() |
                    ForEach-Object { $_.GetTypes() } |
                    Where-Object { $_.Name -eq $c } |
                    Select-Object -First 1

            $type | Should -Not -BeNullOrEmpty
        }
    }
}
