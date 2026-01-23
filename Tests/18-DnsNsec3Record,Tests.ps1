# Test Set 18 - NSEC3 Record Parsing & Wire Encoding
# Run with: Invoke-Pester

using module dnstools

using module dnstools
#Import-Module ('{0}/../DnsSecTools.psd1' -f $PSScriptRoot) -Force

Describe -Name 'NSEC3 Record Parsing and Encoding' -Fixture {

    It -Name 'Parses a simple NSEC3 record' -Test {
        # HashAlgorithm: 1 (SHA-1)
        # Flags:        0
        # Iterations:   10
        # Salt:         "ABCD" (0x41 0x42 0x43 0x44)
        # NextHash:     20 bytes of 0x11
        # Types:        1, 2, 6, 15

        $saltBytes = [byte[]](0x41,0x42,0x43,0x44)

        $nextHashList = [System.Collections.Generic.List[byte]]::new()
        1..20 | ForEach-Object { [void]$nextHashList.Add(0x11) }
        $nextHash = [byte[]]$nextHashList.ToArray()

        # Bitmap for types 1,2,6,15 (same as NSEC)
        # Block 0, length 2 bytes
        $bitmap = [byte[]](0x62, 0x01)  # 0110 0010 → 1,2,6 ; 0000 0001 → 15

        $rdataList = [System.Collections.Generic.List[byte]]::new()

        # HashAlgorithm, Flags
        [void]$rdataList.Add(1)
        [void]$rdataList.Add(0)

        # Iterations = 10 (big-endian: 0x00 0x0A)
        [void]$rdataList.Add(0x00)
        [void]$rdataList.Add(0x0A)

        # Salt length + salt
        [void]$rdataList.Add([byte]$saltBytes.Length)
        [void]$rdataList.AddRange($saltBytes)

        # NextHash length + NextHash
        [void]$rdataList.Add([byte]$nextHash.Length)
        [void]$rdataList.AddRange($nextHash)

        # Type bitmap: block 0, length 2, then bytes
        [void]$rdataList.Add(0)        # Block number
        [void]$rdataList.Add(2)        # Bitmap length
        [void]$rdataList.AddRange($bitmap)

        $bytes = [byte[]]$rdataList.ToArray()

        $nsec3 = [DnsNsec3Record]::Parse($bytes)

        $nsec3.HashAlgorithm | Should -Be 1
        $nsec3.Flags         | Should -Be 0
        $nsec3.Iterations    | Should -Be 10
        $nsec3.Salt          | Should -Be $saltBytes
        $nsec3.NextHash      | Should -Be $nextHash
        $nsec3.Types         | Should -Be @(1,2,6,15)
    }

    It -Name 'Round-trips NSEC3 RDATA correctly' -Test {
        $saltBytes = [byte[]](0x41,0x42,0x43,0x44)

        $nextHashList = [System.Collections.Generic.List[byte]]::new()
        1..20 | ForEach-Object { [void]$nextHashList.Add(0x11) }
        $nextHash = [byte[]]$nextHashList.ToArray()

        $bitmap = [byte[]](0x62, 0x01)

        $rdataList = [System.Collections.Generic.List[byte]]::new()

        [void]$rdataList.Add(1)    # HashAlgorithm
        [void]$rdataList.Add(0)    # Flags
        [void]$rdataList.Add(0x00) # Iterations high byte
        [void]$rdataList.Add(0x0A) # Iterations low byte

        [void]$rdataList.Add([byte]$saltBytes.Length)
        [void]$rdataList.AddRange($saltBytes)

        [void]$rdataList.Add([byte]$nextHash.Length)
        [void]$rdataList.AddRange($nextHash)

        [void]$rdataList.Add(0)    # Block 0
        [void]$rdataList.Add(2)    # Length 2
        [void]$rdataList.AddRange($bitmap)

        $bytes = [byte[]]$rdataList.ToArray()

        $nsec3 = [DnsNsec3Record]::Parse($bytes)
        $out   = $nsec3.ToWire()

        $out | Should -Be $bytes
    }

    It -Name 'Sorts NSEC3 types canonically' -Test {
        $nsec3 = [DnsNsec3Record]::new(
            1,                          # HashAlgorithm
            0,                          # Flags
            10,                         # Iterations
            [byte[]](0x41,0x42),        # Salt
            [byte[]](0x22,0x22,0x22,0x22,0x22,
                     0x22,0x22,0x22,0x22,0x22,
                     0x22,0x22,0x22,0x22,0x22,
                     0x22,0x22,0x22,0x22,0x22), # NextHash (20 bytes)
            [int[]](15,1,6,2)           # Types (unsorted)
        )

        $wire   = $nsec3.ToWire()
        $parsed = [DnsNsec3Record]::Parse($wire)

        $parsed.Types | Should -Be @(1,2,6,15)
    }

    It -Name 'Handles multi-block NSEC3 bitmaps' -Test {
        # Types span block 0 and block 1: 1, 2, 257, 300
        $nsec3 = [DnsNsec3Record]::new(
            1,
            0,
            5,
            [byte[]]@(),                # empty salt
            [byte[]](0x33,0x33,0x33,0x33,0x33,
                     0x33,0x33,0x33,0x33,0x33,
                     0x33,0x33,0x33,0x33,0x33,
                     0x33,0x33,0x33,0x33,0x33), # NextHash (20 bytes)
            [int[]](1,2,257,300)
        )

        $wire   = $nsec3.ToWire()
        $parsed = [DnsNsec3Record]::Parse($wire)

        $parsed.Types | Should -Be @(1,2,257,300)
    }
}
