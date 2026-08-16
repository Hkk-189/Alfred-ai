<#!
.SYNOPSIS
Runs Alfred from its project-local Windows virtual environment.
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'

if (-not (Test-Path $VenvPython)) {
    throw "Alfred is not set up yet. Run .\scripts\setup-windows.ps1 from $ProjectRoot first."
}

& $VenvPython (Join-Path $ProjectRoot 'main.py') @Arguments
exit $LASTEXITCODE
