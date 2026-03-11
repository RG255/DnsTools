using module dnstools

param(
    [string]$OutputPath = (Join-Path -Path (Split-Path -path $PSSCriptroot -parent) -ChildPath 'Tests\Fixtures')
)

if (-not (Test-Path $OutputPath)) {
    $null = New-Item -ItemType Directory -Path $OutputPath
}

function Write-Fixture {
		param(
				[string]$Name,
				[byte[]]$Bytes
		)

		$path = Join-Path -Path $OutputPath -ChildPath $Name
		[IO.File]::WriteAllBytes($path, $Bytes)
		[string]$bl = $Bytes.Length
		Write-Host ('Wrote {0} {1} {2}' -f $Path, $Bl, 'bytes')
}

# ============================================================
# Helper: build typed A/AAAA RDATA using the new Parse API
# ============================================================

function New-ARecordObject {
    param([string]$Address)

    $bytes  = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
    $reader = [DnsBinaryReader]::new($bytes)
    $obj    = [DnsARecord]::Parse($reader, $bytes.Length)

    return @{ Bytes = $bytes; Object = $obj }
}

function New-AaaaRecordObject {
    param([string]$Address)

    $bytes  = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
    $reader = [DnsBinaryReader]::new($bytes)
    $obj    = [DnsAaaaRecord]::Parse($reader, $bytes.Length)

    return @{ Bytes = $bytes; Object = $obj }
}

# ============================================================
# Helper: minimal A record response
# ============================================================

function New-SimpleAResponse {
    param(
        [string]$Name,
        [string]$Address
    )

    $hdr = [DnsHeader]::new(
        0x1234,
        0x8180,
        1, 1, 0, 0
    )

    $q = [DnsQuestion]::new($Name, 1, 1)

    $a = New-ARecordObject -Address $Address

    $rr = [DnsResourceRecord]::new(
        $Name,
        1,
        1,
        300,
        $a.Bytes,
        $a.Object
    )

    $pkt = [DnsPacket]::new()
    $pkt.Header = $hdr
    $pkt.Questions.Add($q)
    $pkt.Answers.Add($rr)

    return $pkt.ToArray()
}

# ============================================================
# 0. Compression Fixture
# ============================================================

function New-CompressedNameFixture {
    $w = [DnsBinaryWriter]::new()

    $w.WriteUInt16BE(0xAAAA)
    $w.WriteUInt16BE(0x8180)
    $w.WriteUInt16BE(1)
    $w.WriteUInt16BE(1)
    $w.WriteUInt16BE(0)
    $w.WriteUInt16BE(0)

    $w.WriteName('www.example.com')
    $w.WriteUInt16BE(5)
    $w.WriteUInt16BE(1)

    $w.WriteByte(0xC0)
    $w.WriteByte(12)

    $w.WriteUInt16BE(5)
    $w.WriteUInt16BE(1)
    $w.WriteUInt32BE(300)
    $w.WriteUInt16BE(2)

    $w.WriteByte(0xC0)
    $w.WriteByte(12)

    return $w.ToArray()
}

Write-Fixture -Name 'compressed-name.bin' -Bytes (New-CompressedNameFixture)

# ============================================================
# 1. DoT Fixtures
# ============================================================

Write-Fixture -Name 'dot-simple-response.bin' -Bytes (New-SimpleAResponse -Name 'example.com' -Address '192.0.2.10')
Write-Fixture -Name 'simple-a-record.bin'      -Bytes (New-SimpleAResponse -Name 'www.example.com' -Address '192.0.2.123')

# Large response
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x2222, 0x8180, 1, 5, 0, 0)
$pkt.Questions.Add([DnsQuestion]::new('large.example.com', 1, 1))

for ($i = 1; $i -le 5; $i++) {
    $ip = "203.0.113.$i"
    $a  = New-ARecordObject -Address $ip

    $rr = [DnsResourceRecord]::new(
        'large.example.com',
        1,
        1,
        300,
        $a.Bytes,
        $a.Object
    )

    $pkt.Answers.Add($rr)
}

Write-Fixture -Name 'dot-large-response.bin' -Bytes ($pkt.ToArray())

# ============================================================
# 2. DoH Fixtures
# ============================================================

Write-Fixture -Name 'doh-simple-response.bin' -Bytes (New-SimpleAResponse -Name 'example.com' -Address '192.0.2.20')
Write-Fixture -Name 'doh-large-response.bin'  -Bytes ($pkt.ToArray())

# ============================================================
# 3. DNSSEC Canonicalization Fixtures
# ============================================================

$nameWire = Get-DnssecCanonicalNameWire -name 'www.Example.COM'
Write-Fixture -Name 'canonical-name-wire.bin' -Bytes $nameWire

$rr1 = [DnsResourceRecord]::new('a.example', 1, 1, 300, ([byte[]](1,2,3,4)), $null)
$rr2 = [DnsResourceRecord]::new('a.example', 1, 1, 300, ([byte[]](1,2,3,5)), $null)
$rrset = @($rr1, $rr2)

$sorted = Get-DnssecCanonicalRrsetData -Rrset $rrset
$Bytes = New-Object System.Collections.Generic.List[byte]
foreach ($rec in $sorted) { $Bytes.AddRange($rec.RdataWire) }

Write-Fixture -Name 'canonical-rrset.bin' -Bytes ($Bytes.ToArray())

$rrsig = [DnsRrsigRecord]::new(1, 8, 2, 300, 1000, 900, 12345, 'example.com', ([byte[]](1..32)))
$sd = Get-DnssecSignedData -Rrsig $rrsig -Rrset $rrset
Write-Fixture -Name 'signed-data.bin' -Bytes $sd

# ============================================================
# 4. Resolver Edge Case Fixtures
# ============================================================

# Broken glue
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x3333, 0x8180, 1, 0, 1, 1)
$pkt.Questions.Add([DnsQuestion]::new('broken.example', 1, 1))

$w = [DnsBinaryWriter]::new()
$w.WriteName('ns1.broken.example')
$nsRdata = $w.ToArray()

$pkt.Authority.Add([DnsResourceRecord]::new('broken.example', 2, 1, 300, $nsRdata, [DnsNsRecord]::new('ns1.broken.example')))
$pkt.Additional.Add([DnsResourceRecord]::new('wrong.example', 1, 1, 300, ([byte[]](10,0,0,1)), $null))

Write-Fixture -Name 'referral-broken-glue.bin' -Bytes ($pkt.ToArray())

# Mismatched NS
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x4444, 0x8180, 1, 0, 1, 0)
$pkt.Questions.Add([DnsQuestion]::new('mismatch.example', 1, 1))

$w = [DnsBinaryWriter]::new()
$w.WriteName('ns99.example')
$nsRdata = $w.ToArray()

$pkt.Authority.Add([DnsResourceRecord]::new('mismatch.example', 2, 1, 300, $nsRdata, [DnsNsRecord]::new('ns99.example')))

Write-Fixture -Name 'referral-mismatched-ns.bin' -Bytes ($pkt.ToArray())

# Empty authority
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x5555, 0x8180, 1, 0, 0, 0)
$pkt.Questions.Add([DnsQuestion]::new('empty.example', 1, 1))

Write-Fixture -Name 'referral-empty-authority.bin' -Bytes ($pkt.ToArray())

# Cyclic NS
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x6666, 0x8180, 1, 0, 1, 0)
$pkt.Questions.Add([DnsQuestion]::new('cycle.example', 1, 1))

$w = [DnsBinaryWriter]::new()
$w.WriteName('cycle.example')
$nsRdata = $w.ToArray()

$pkt.Authority.Add([DnsResourceRecord]::new('cycle.example', 2, 1, 300, $nsRdata, [DnsNsRecord]::new('cycle.example')))

Write-Fixture -Name 'referral-cyclic-ns.bin' -Bytes ($pkt.ToArray())

# Correct referral-with-glue
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x7777, 0x8180, 1, 0, 1, 1)
$pkt.Questions.Add([DnsQuestion]::new('ns1.example.net', 1, 1))

$w = [DnsBinaryWriter]::new()
$w.WriteName('ns1.example.net')
$nsRdata = $w.ToArray()

$pkt.Authority.Add([DnsResourceRecord]::new('example.net', 2, 1, 300, $nsRdata, [DnsNsRecord]::new('ns1.example.net')))

$a = New-ARecordObject -Address '192.0.2.53'
$pkt.Additional.Add([DnsResourceRecord]::new('ns1.example.net', 1, 1, 300, $a.Bytes, $a.Object))

Write-Fixture -Name 'referral-with-glue.bin' -Bytes ($pkt.ToArray())

# Correct referral-no-glue
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x8888, 0x8180, 1, 0, 1, 0)
$pkt.Questions.Add([DnsQuestion]::new('ns1.deep.example', 1, 1))

$w = [DnsBinaryWriter]::new()
$w.WriteName('ns1.deep.example')
$nsRdata = $w.ToArray()

$pkt.Authority.Add([DnsResourceRecord]::new('deep.example', 2, 1, 300, $nsRdata, [DnsNsRecord]::new('ns1.deep.example')))

Write-Fixture -Name 'referral-no-glue.bin' -Bytes ($pkt.ToArray())

# Test 06 fixtures: Iterative resolution chain
# Root referral: www.example.com -> .com NS with glue
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x1111, 0x8180, 1, 0, 1, 1)
$pkt.Questions.Add([DnsQuestion]::new('www.example.com', 1, 1))

$w = [DnsBinaryWriter]::new()
$w.WriteName('ns1.com')
$nsRdata = $w.ToArray()
$pkt.Authority.Add([DnsResourceRecord]::new('com', 2, 1, 300, $nsRdata, [DnsNsRecord]::new('ns1.com')))

$a = New-ARecordObject -Address '192.0.2.10'
$pkt.Additional.Add([DnsResourceRecord]::new('ns1.com', 1, 1, 300, $a.Bytes, $a.Object))

Write-Fixture -Name 'test06-root-referral.bin' -Bytes ($pkt.ToArray())

# TLD referral: www.example.com -> example.com NS with glue
$pkt = [DnsPacket]::new()
$pkt.Header = [DnsHeader]::new(0x2222, 0x8180, 1, 0, 1, 1)
$pkt.Questions.Add([DnsQuestion]::new('www.example.com', 1, 1))

$w = [DnsBinaryWriter]::new()
$w.WriteName('ns1.example.com')
$nsRdata = $w.ToArray()
$pkt.Authority.Add([DnsResourceRecord]::new('example.com', 2, 1, 300, $nsRdata, [DnsNsRecord]::new('ns1.example.com')))

$a = New-ARecordObject -Address '192.0.2.53'
$pkt.Additional.Add([DnsResourceRecord]::new('ns1.example.com', 1, 1, 300, $a.Bytes, $a.Object))

Write-Fixture -Name 'test06-tld-referral.bin' -Bytes ($pkt.ToArray())

Write-Host "Extended fixtures generated in $OutputPath"
