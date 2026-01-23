param(
    [switch]$Clean
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = Join-Path $root "src"
$tests = Join-Path $root "Tests"
$out = Join-Path $root "out"

if ($Clean) {
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
}

if (-not (Test-Path $out)) {
    New-Item -ItemType Directory -Path $out | Out-Null
}

Write-Host "Running Pester tests..."
Invoke-Pester -Path $tests -Output Detailed

Write-Host "Copying module files..."
Copy-Item "$src\*.ps1" $out -Force

Write-Host "Build complete."
