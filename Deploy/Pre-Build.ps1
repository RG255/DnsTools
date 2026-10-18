# Pre-build hook for DnsTools (picked up by Tools\Invoke-ModuleReleaseChecks.ps1, Tools\Invoke-AllModuleTest.ps1 and
# Tools\Invoke-ModuleTest.ps1, which run it BEFORE anything is checked or tested).
#
# DnsTools.psm1 is GENERATED: the class section is assembled from Classes\*.ps1 and the module-init tail from
# Helpers\DnsTools-psm1-Tail.ps1 by Helpers\GenPsm1File.ps1. A hand edit to the psm1 is lost, and a class-file edit
# does nothing until the psm1 is rebuilt - so every check/test run rebuilds it first. Rebuilding every time is
# deliberate (the output is byte-identical when nothing changed).
#
# Exit code: 0 rebuilt, non-zero = could not rebuild (the caller must stop).

$ErrorActionPreference = 'Stop'

$generator = Join-Path -Path $PSScriptRoot -ChildPath '..\Helpers\GenPsm1File.ps1'

try
{
	& $generator
	if ($LASTEXITCODE -and $LASTEXITCODE -ne 0)
	{ exit $LASTEXITCODE }
}
catch
{
	Write-Host ('DnsTools pre-build failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
	exit 1
}
exit 0
