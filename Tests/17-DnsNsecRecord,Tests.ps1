# Test Set 17 - NSEC Record Parsing & Wire Encoding
# Run with: Invoke-Pester

using module dnstools

using module 'D:\PowerShellScripts\RawDns\0.3\DnsSecTools.psm1'
#Import-Module ('{0}/../DnsSecTools.psd1' -f $PSScriptRoot) -Force

Describe -Name 'NSEC Record Parsing and Encoding' -Fixture {

    It -Name 'Parses a simple NSEC record' -Test {
        # next: a.example.com
        # types: 1, 2, 6, 15

        $rdata = [byte[]](
            1, 0x61,                                 # "a"
            7, 0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,    # "example"
            3, 0x63,0x6f,0x6d,                        # "com"
            0,                                        # root
            0, 2,                                     # block 0, length 2 bytes
            0x62,                                     # 0110 0010 → types 1, 2, 6
            0x01                                      # 0000 0001 → type 15
        )

        $nsec = [DnsNsecRecord]::Parse($rdata)

        $nsec.NextDomainName | Should -Be 'a.example.com'
        $nsec.Types          | Should -Contain 1
        $nsec.Types          | Should -Contain 2
        $nsec.Types          | Should -Contain 6
        $nsec.Types          | Should -Contain 15
    }

    It -Name 'Round-trips NSEC RDATA correctly' -Test {
        $rdata = [byte[]](
            1, 0x61,
            7, 0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,
            3, 0x63,0x6f,0x6d,
            0,
            0, 2,
            0x62,                                     # 0110 0010 → types 1, 2, 6
            0x01                                      # 0000 0001 → type 15
        )

        $nsec = [DnsNsecRecord]::Parse($rdata)
        $out  = $nsec.ToWire()

        $out | Should -Be $rdata
    }

    It -Name 'Sorts NSEC types canonically' -Test {
        $nsec = [DnsNsecRecord]::new(
            'a.example.com',
            [int[]](15, 1, 6, 2)
        )

        $wire   = $nsec.ToWire()
        $parsed = [DnsNsecRecord]::Parse($wire)

        $parsed.Types | Should -Be @(1, 2, 6, 15)
    }

    It -Name 'Handles multi-block NSEC bitmaps' -Test {
        # Types span block 0 and block 1
        $nsec = [DnsNsecRecord]::new(
            'next.example.com',
            [int[]](1, 2, 257, 300)
        )

        $wire   = $nsec.ToWire()
        $parsed = [DnsNsecRecord]::Parse($wire)

        $parsed.Types | Should -Be @(1, 2, 257, 300)
    }
}
