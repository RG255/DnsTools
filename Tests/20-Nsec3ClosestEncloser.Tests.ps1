using module dnstools

InModuleScope DnsTools {


Describe -Name 'NSEC3 Closest Encloser' -Fixture {
	#
	# Make the hash helper visible to all tests
	#
	BeforeAll {
		function _TestHash 
		{
			param(
				[string]$Name,
				[int]$Algo,
				[int]$Iter,
				[byte[]]$Salt
			)

			# EXACT same canonicalization as CE
			$canon = $Name.ToLower().TrimEnd('.') + '.'

			Get-DnssecNsec3Hash -Name $canon -Algorithm $Algo -Iterations $Iter -Salt $Salt
		}
	}

	It -Name 'Finds the closest encloser when the exact name is present' -Test {
		# Query: a.b.example.com
		# CE: b.example.com

		$Salt = [byte[]](0x12, 0x34)
		$Algo = 1
		$Iter = 5

		# Compute real NSEC3 owner hashes
		$hash_example = _TestHash 'example.com'     $Algo $Iter $Salt
		$hash_b       = _TestHash 'b.example.com'   $Algo $Iter $Salt

		# Build NSEC3 records (OwnerHash + NextHash)
		$nsec3_example = [DnsNsec3Record]::new(
			$Algo,0,$Iter,$Salt,
			$hash_example,   # OwnerHash
			$hash_example,   # NextHash (not used in CE logic)
			[int[]]@()
		)

		$nsec3_b = [DnsNsec3Record]::new(
			$Algo,0,$Iter,$Salt,
			$hash_b,         # OwnerHash
			$hash_b,         # NextHash
			[int[]]@()
		)

		$records = @($nsec3_example, $nsec3_b)

		$result = Find-DnssecNsec3ClosestEncloser `
		-QueryName 'a.b.example.com' `
		-Nsec3Records $records `
		-HashAlgorithm $Algo `
		-Iterations $Iter `
		-Salt $Salt

		$result.Name   | Should -Be 'b.example.com'
		$result.Hash   | Should -Be $hash_b
		$result.Record | Should -Be $nsec3_b
	}

	It -Name 'Falls back to parent when deeper labels do not exist' -Test {
		# Query: x.y.z.example.com
		# CE: example.com

		$Salt = [byte[]](0x12, 0x34)
		$Algo = 1
		$Iter = 5

		$hash_example = _TestHash 'example.com' $Algo $Iter $Salt

		$nsec3_example = [DnsNsec3Record]::new(
			$Algo,0,$Iter,$Salt,
			$hash_example,   # OwnerHash
			$hash_example,   # NextHash
			[int[]]@()
		)

		$records = @($nsec3_example)

		$result = Find-DnssecNsec3ClosestEncloser `
		-QueryName 'x.y.z.example.com' `
		-Nsec3Records $records `
		-HashAlgorithm $Algo `
		-Iterations $Iter `
		-Salt $Salt

		$result.Name | Should -Be 'example.com'
	}

	It -Name 'Returns $null when no ancestor exists in the NSEC3 chain' -Test {
		$Salt = [byte[]](0x12, 0x34)
		$Algo = 1
		$Iter = 5

		$records = @()

		$result = Find-DnssecNsec3ClosestEncloser `
		-QueryName 'a.b.example.com' `
		-Nsec3Records $records `
		-HashAlgorithm $Algo `
		-Iterations $Iter `
		-Salt $Salt

		$result | Should -Be $null
	}
}
}
