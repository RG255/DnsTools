$root = "D:\PowerShellScripts\DnsTools\0.4\Classes"

Get-ChildItem -Path $root -Recurse -Filter *.ps1 | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    # Rewrite without BOM
    [System.IO.File]::WriteAllText($_.FullName, $content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Fixed BOM in $($_.FullName)"
}
