# Assume you have raw DNS response bytes in $bytes
$packet = Parse-DnsPacket -Packet $bytes

$packet.ID
$packet.Flags
$packet.Questions
$packet.Answers | Format-Table Name,Type,TTL

# Look at RRSIGs
$packet.Answers |
		Where-Object { $_.Type -eq 46 } |
		ForEach-Object { $_.RData }  # these are DnsRrsigRecord

#=============================

# 1) Get all A records for example.com and their RRSIG
$rrset = $packet.Answers | Where-Object { $_.Name.Text -eq "example.com" -and $_.Type -eq 1 }
$rrsig = $packet.Answers | Where-Object { $_.Name.Text -eq "example.com" -and $_.Type -eq 46 } | Select-Object -First 1

# 2) Get DNSKEY RRset for the zone
$dnskeys = $packet.Additional | Where-Object { $_.Type -eq 48 }

# 3) Validate
$result = Test-DnssecRrsig -Rrsig $rrsig.RData -Rrset $rrset -DnskeyRrset $dnskeys
$result

#=================================

# From parent (e.g. .net TLD response)
$parentDsRrset = $parentPacket.Answers |
    Where-Object { $_.Type -eq 43 -and $_.Name.Text -eq "verteiltesysteme.net" }

# From child zone (verteiltesysteme.net)
$childDnskeyRrset = $childPacket.Answers + $childPacket.Additional |
    Where-Object { $_.Type -eq 48 -and $_.Name.Text -eq "verteiltesysteme.net" }

$targetRrset = $childPacket.Answers |
    Where-Object { $_.Name.Text -eq "www.verteiltesysteme.net" -and $_.Type -eq 1 }  # A records

$targetRrsig = $childPacket.Answers |
    Where-Object { $_.Name.Text -eq "www.verteiltesysteme.net" -and $_.Type -eq 46 } |
    Select-Object -First 1

$result = Test-DnssecChain `
    -ParentDsRrset $parentDsRrset `
    -ChildDnskeyRrset $childDnskeyRrset `
    -TargetRrset $targetRrset `
    -TargetRrsig $targetRrsig.RData `
    -ChildZoneName "verteiltesysteme.net"

$result

#=======================================
# Ask for A records and validate DNSSEC chain
$result = Resolve-Dnssec -Name "www.example.com" -Type 1 -Server "8.8.8.8"

$result.Valid
$result.Stage
$result.Reason
$result.Answers | Select-Object Name,Type,TTL,RData


#==========================
Test-DnssecName -Name "www.example.com" -Type 1
