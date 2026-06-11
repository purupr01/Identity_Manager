# ==============================================================================
#  Identity Manager - PowerShell Build Script
#  ITProAcademy.co.in
#
#  Run as Administrator:
#    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#    .\build_exe.ps1
# ==============================================================================

Set-StrictMode -Off
$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "Identity Manager - Build Script"

function Write-Header  { param($msg) Write-Host "" ; Write-Host $msg -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "  [!!]  $msg" -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "  [XX]  $msg" -ForegroundColor Red }
function Write-Info    { param($msg) Write-Host "  -->   $msg" -ForegroundColor White }

Clear-Host
Write-Host "===========================================================" -ForegroundColor Blue
Write-Host "   Identity Manager - EXE Build Script  v1.1               " -ForegroundColor White
Write-Host "   ITProAcademy.co.in  (onedir - AV-safe build)            " -ForegroundColor DarkCyan
Write-Host "===========================================================" -ForegroundColor Blue

# -- Step 1: Verify running as Administrator -----------------------------------
Write-Header "Step 1: Checking administrator privileges..."
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail "This script must be run as Administrator."
    Write-Info "Right-click PowerShell -> 'Run as administrator', then re-run this script."
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Success "Running as Administrator."

# -- Step 2: Locate Python ----------------------------------------------------
Write-Header "Step 2: Locating Python 3.8+..."

$pythonCmd = $null
$pythonVersion = $null

foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -eq 3 -and $minor -ge 8) {
                $pythonCmd = $cmd
                $pythonVersion = "$major.$minor"
                break
            }
        }
    } catch { }
}

if ($null -eq $pythonCmd) {
    Write-Warn "Python 3.8+ not found. Attempting silent install of Python 3.11..."
    $pyInstaller = "$env:TEMP\python-3.11-installer.exe"
    $pyUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    Write-Info "Downloading Python 3.11 installer..."
    try {
        Invoke-WebRequest -Uri $pyUrl -OutFile $pyInstaller -UseBasicParsing
        Write-Info "Running silent install (this may take 1-2 minutes)..."
        Start-Process -FilePath $pyInstaller -ArgumentList "/quiet InstallAllUsers=0 PrependPath=1 Include_pip=1" -Wait
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        $ver = & python --version 2>&1
        if ($ver -match "Python 3\.(\d+)") {
            $pythonCmd = "python"
            $pythonVersion = "3.$($Matches[1])"
            Write-Success "Python $pythonVersion installed successfully."
        } else {
            throw "Install verification failed"
        }
    } catch {
        Write-Fail "Automatic Python install failed: $_"
        Write-Info "Please install Python 3.11 manually from: https://www.python.org/downloads/"
        Write-Info "Tick 'Add Python to PATH' during install, then re-run this script."
        Read-Host "Press Enter to exit"
        exit 1
    }
} else {
    Write-Success "Found Python $pythonVersion at: $pythonCmd"
}

# -- Step 3: Upgrade pip -------------------------------------------------------
Write-Header "Step 3: Upgrading pip..."
& $pythonCmd -m pip install --upgrade pip --quiet
Write-Success "pip is up to date."

# -- Step 4: Install dependencies ---------------------------------------------
Write-Header "Step 4: Installing/upgrading dependencies..."
$packages = @("ldap3>=2.9.1", "openpyxl>=3.1.0", "reportlab>=4.0.0", "Pillow>=10.0.0", "pyinstaller>=6.0.0")
foreach ($pkg in $packages) {
    Write-Info "Installing $pkg ..."
    & $pythonCmd -m pip install $pkg --upgrade --quiet
}
Write-Success "All packages installed."

# -- Step 5: Clean previous build artefacts -----------------------------------
Write-Header "Step 5: Cleaning previous build artefacts..."
@("build", "dist", "__pycache__") | ForEach-Object {
    if (Test-Path $_) {
        Remove-Item -Recurse -Force $_
        Write-Info "Removed $_"
    }
}
Write-Success "Clean complete."

# -- Step 6: Build IdentityManager (onedir - AV-safe) -------------------------
Write-Header "Step 6: Building IdentityManager folder (this takes 2-5 minutes)..."
Write-Info "Using --onedir mode (folder deployment) to avoid Windows Defender false positives."
Write-Info "PyInstaller logs appear below - red text is normal PyInstaller output, not real errors."
$buildStart = Get-Date
# Temporarily allow stderr so PyInstaller INFO lines do not trigger NativeCommandError.
# $ErrorActionPreference = "Stop" causes PS to treat any stderr as a fatal error;
# setting it to Continue for the duration of the PyInstaller call prevents that.
$savedEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $pythonCmd -m PyInstaller identity_manager.spec --clean --noconfirm
$ErrorActionPreference = $savedEAP
$buildEnd = Get-Date
$elapsed  = [math]::Round(($buildEnd - $buildStart).TotalSeconds, 1)

if (Test-Path "dist\IdentityManager\IdentityManager.exe") {
    $folderSize = (Get-ChildItem "dist\IdentityManager" -Recurse | Measure-Object -Property Length -Sum).Sum
    $folderMB   = [math]::Round($folderSize / 1MB, 1)
    Write-Success "IdentityManager folder built! ($folderMB MB total, $elapsed seconds)"
    Write-Info "Output: dist\IdentityManager\IdentityManager.exe"
} else {
    Write-Fail "dist\IdentityManager\IdentityManager.exe NOT found - check errors above."
    Read-Host "Press Enter to exit"
    exit 1
}

# -- Step 7: Build IDManager_KeyGen.exe ---------------------------------------
Write-Header "Step 7: Building IDManager_KeyGen.exe (single-file console tool)..."
$keyStart = Get-Date
$savedEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $pythonCmd -m PyInstaller IDManager_KeyGen.spec --clean --noconfirm
$ErrorActionPreference = $savedEAP
$keyEnd     = Get-Date
$keyElapsed = [math]::Round(($keyEnd - $keyStart).TotalSeconds, 1)

if (Test-Path "dist\IDManager_KeyGen.exe") {
    $keyMB = [math]::Round((Get-Item "dist\IDManager_KeyGen.exe").Length / 1MB, 1)
    Write-Success "IDManager_KeyGen.exe built! ($keyMB MB, $keyElapsed seconds)"
} else {
    Write-Warn "IDManager_KeyGen.exe not created (non-critical - main app still works)."
}

# -- Step 8: Create deployment ZIP --------------------------------------------
Write-Header "Step 8: Creating deployment ZIP..."
$zipPath = "dist\IdentityManager_Deploy.zip"
try {
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "dist\IdentityManager" -DestinationPath $zipPath
    $zipMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    Write-Success "Deployment ZIP created: $zipPath ($zipMB MB)"
    Write-Info "Unzip on target server to e.g. C:\Tools\IdentityManager\ and run IdentityManager.exe"
} catch {
    Write-Warn "Could not create ZIP: $_ (non-critical - deploy the folder directly)"
}

# -- Done ----------------------------------------------------------------------
Write-Host ""
Write-Host "===========================================================" -ForegroundColor Green
Write-Host "   BUILD COMPLETE                                           " -ForegroundColor White
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Output in dist\:" -ForegroundColor White
Write-Host "  IdentityManager\           -> Copy this FOLDER to target machines" -ForegroundColor Cyan
Write-Host "  IdentityManager_Deploy.zip -> ZIP of above, easy to transfer" -ForegroundColor Cyan
Write-Host "  IDManager_KeyGen.exe       -> Keep on admin machine ONLY" -ForegroundColor Yellow
Write-Host ""
Write-Host "  DEPLOYMENT STEPS:" -ForegroundColor White
Write-Host "  1. Copy IdentityManager_Deploy.zip to each target server" -ForegroundColor White
Write-Host "  2. Unzip to C:\Tools\IdentityManager\" -ForegroundColor White
Write-Host "  3. Add C:\Tools\IdentityManager\ to Windows Defender exclusions:" -ForegroundColor White
Write-Host "     Defender -> Virus & threat protection -> Exclusions -> Add folder" -ForegroundColor DarkGray
Write-Host "  4. Run IdentityManager.exe from inside the folder" -ForegroundColor White
Write-Host "  5. Help -> Activate Software -> enter activation code" -ForegroundColor White
Write-Host ""
Write-Host "  WHY A FOLDER INSTEAD OF ONE EXE?" -ForegroundColor Yellow
Write-Host "  The previous single-EXE build extracted files to %TEMP% at runtime." -ForegroundColor DarkGray
Write-Host "  Defender flags this as dropper-malware behaviour." -ForegroundColor DarkGray
Write-Host "  The folder build eliminates runtime extraction entirely." -ForegroundColor DarkGray
Write-Host ""

try { Start-Process explorer.exe "dist" } catch { }
Read-Host "Press Enter to exit"
