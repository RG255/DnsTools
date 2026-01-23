$path = "D:\PowerShellScripts\DnsTools\0.4\DnsTools.psd1"

# Read as UTF-16
$content = Get-Content $path -Raw

# Write as UTF-8 (no BOM)
[System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($false))
