# scopeward installer (Windows / PowerShell).
# Installs scopeward (stdlib-only, no runtime deps) into the current Python
# environment as an editable install. Pass -Dev for the test extras.
[CmdletBinding()]
param(
    [switch]$Dev
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
Write-Host "scopeward: using $(& $py --version)"

$target = "."
if ($Dev) {
    $target = ".[dev]"
    Write-Host "scopeward: installing with dev (test) extras"
}

& $py -m pip install -e $target
if ($LASTEXITCODE -ne 0) { throw "pip install failed with exit code $LASTEXITCODE" }

Write-Host "scopeward: installed. Try: scopeward --version"
