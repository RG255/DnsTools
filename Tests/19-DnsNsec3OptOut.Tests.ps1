# Test Set 19 - NSEC3 Opt-Out Logic
# Run with: Invoke-Pester

using module dnstools

using module dnstools
#Import-Module ('{0}/../DnsSecTools.psd1' -f $PSScriptRoot) -Force

Describe 'NSEC3 Opt-Out Behaviour' {

    It 'Allows a gap when Opt-Out flag is set and skipped name is a delegation' {
        $nextHash = [byte[]](0..19 | ForEach-Object { 0xAA })

        $nsec3 = [DnsNsec3Record]::new(
            1,      # HashAlgorithm
            1,      # Flags (Opt-Out)
            10,     # Iterations
            [byte[]]@(),
            $nextHash,
            [int[]]@()
        )

        $isDelegation = $true

        $result = Test-DnssecNsec3OptOut -Nsec3 $nsec3 -IsDelegation $isDelegation

        $result | Should -Be $true
    }

    It 'Rejects a gap when Opt-Out flag is set but skipped name is NOT a delegation' {
        $nextHash = [byte[]](0..19 | ForEach-Object { 0xAA })

        $nsec3 = [DnsNsec3Record]::new(
            1,
            1,
            10,
            [byte[]]@(),
            $nextHash,
            [int[]]@()
        )

        $isDelegation = $false

        $result = Test-DnssecNsec3OptOut -Nsec3 $nsec3 -IsDelegation $isDelegation

        $result | Should -Be $false
    }

    It 'Rejects a gap when Opt-Out flag is NOT set' {
        $nextHash = [byte[]](0..19 | ForEach-Object { 0xAA })

        $nsec3 = [DnsNsec3Record]::new(
            1,
            0,      # Flags = 0 → no Opt-Out
            10,
            [byte[]]@(),
            $nextHash,
            [int[]]@()
        )

        $isDelegation = $true

        $result = Test-DnssecNsec3OptOut -Nsec3 $nsec3 -IsDelegation $isDelegation

        $result | Should -Be $false
    }
}
