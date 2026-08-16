<#!
.SYNOPSIS
Creates or repairs Alfred's Windows virtual environment.

.DESCRIPTION
Uses the Windows Python launcher, creates .venv in the project root, and
installs Alfred's dependencies. Re-running this script is safe: it reuses the
existing virtual environment and refreshes the installed package.
#>
[CmdletBinding()]
param(
    [switch]$Dev
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot '.venv'
$VenvPython = Join-Path $VenvPath 'Scripts\python.exe'

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python Launcher (py.exe) was not found. Install Python 3.8 or later from https://www.python.org/downloads/windows/ and select 'Install launcher for all users'."
}

if (-not (Test-Path $VenvPython)) {
    Write-Host 'Ensuring pip is available for the selected Python installation...'
    & py -3 -m ensurepip --upgrade
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to bootstrap pip. Reinstall Python with pip enabled, then run this script again."
    }

    Write-Host "Creating virtual environment at $VenvPath..."
    & py -3 -m venv $VenvPath
    if ($LASTEXITCODE -ne 0) {
        throw 'Virtual environment creation failed.'
    }
}

Write-Host 'Upgrading pip...'
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to upgrade pip in .venv.'
}

$InstallTarget = if ($Dev) { "${ProjectRoot}[dev]" } else { $ProjectRoot }
Write-Host "Installing Alfred from $ProjectRoot..."
& $VenvPython -m pip install --editable $InstallTarget
if ($LASTEXITCODE -ne 0) {
    throw 'Dependency installation failed.'
}

& $VenvPython -c "import requests, yaml; print('Alfred dependencies are ready.')"
if ($LASTEXITCODE -ne 0) {
    throw 'Installed dependencies could not be imported.'
}

Write-Host ''
Write-Host 'Setup complete. Start Alfred with:'
Write-Host '  .\scripts\run-windows.ps1'
if (-not $Dev) {
    Write-Host 'For test dependencies, run:'
    Write-Host '  .\scripts\setup-windows.ps1 -Dev'
}
