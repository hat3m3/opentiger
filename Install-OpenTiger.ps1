$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot

function Invoke-Checked {
    param([string]$Executable, [string[]]$CommandArguments)
    & $Executable @CommandArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Executable $CommandArguments"
    }
}

try {
    Write-Host "`nOpenTiger installation" -ForegroundColor Yellow
    $VenvPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        $Launcher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($Launcher) {
            Invoke-Checked -Executable $Launcher.Source -CommandArguments @('-3', '-c', 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)')
            Invoke-Checked -Executable $Launcher.Source -CommandArguments @('-3', '-m', 'venv', (Join-Path $ProjectRoot '.venv'))
        } else {
            $Launcher = Get-Command python.exe -ErrorAction SilentlyContinue
            if (-not $Launcher) { throw 'Python 3.11 or later is required. Install Python, then run this installer again.' }
            Invoke-Checked -Executable $Launcher.Source -CommandArguments @('-c', 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)')
            Invoke-Checked -Executable $Launcher.Source -CommandArguments @('-m', 'venv', (Join-Path $ProjectRoot '.venv'))
        }
    }
    Invoke-Checked -Executable $VenvPython -CommandArguments @('-m', 'pip', 'install', '-r', (Join-Path $ProjectRoot 'requirements.txt'))
    Invoke-Checked -Executable $VenvPython -CommandArguments @('-m', 'pip', 'check')

    $CommandFolder = Join-Path $env:USERPROFILE '.local\bin'
    New-Item -ItemType Directory -Path $CommandFolder -Force | Out-Null
    $CommandFile = Join-Path $CommandFolder 'opentiger.cmd'
    $EntryScript = Join-Path $ProjectRoot 'opentiger-launch.py'
    # Batch files escape literal percent signs by doubling them.
    $QuotedPython = $VenvPython.Replace('%', '%%')
    $QuotedEntry = $EntryScript.Replace('%', '%%')
    $Batch = "@echo off`r`nsetlocal`r`nchcp 65001 >nul`r`n`"$QuotedPython`" `"$QuotedEntry`" %*`r`nexit /b %errorlevel%`r`n"
    [IO.File]::WriteAllText($CommandFile, $Batch, (New-Object Text.UTF8Encoding($false)))

    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $PathEntries = @($UserPath -split ';' | Where-Object { $_ })
    if (-not ($PathEntries | Where-Object { $_.TrimEnd('\') -ieq $CommandFolder.TrimEnd('\') })) {
        [Environment]::SetEnvironmentVariable('Path', (($PathEntries + $CommandFolder) -join ';'), 'User')
    }
    if (-not (($env:Path -split ';') -contains $CommandFolder)) { $env:Path += ";$CommandFolder" }
    # Notify Explorer so newly opened terminals receive the updated user PATH.
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class OpenTigerEnvironment {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr wparam,
        string lparam, uint flags, uint timeout, out UIntPtr result);
}
'@
    $BroadcastResult = [UIntPtr]::Zero
    [void][OpenTigerEnvironment]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$BroadcastResult)

    Invoke-Checked -Executable $VenvPython -CommandArguments @($EntryScript, '--version')
    Write-Host "`nInstalled. Open a new terminal and type: opentiger" -ForegroundColor Green
    Write-Host 'Keep this project folder in place. If you move it, run this installer again.'
} catch {
    Write-Host "`nInstallation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
