# Identity Manager — Windows Build Package
### ITProAcademy.co.in | Active Directory Management Tool | v1.0

---

## What's in this package

| File | Purpose |
|---|---|
| `identity_manager.py` | Main application source |
| `generate_activation.py` | Activation key generator source |
| `build_exe.ps1` | ✅ **Recommended** — PowerShell build script (auto-installs Python if missing) |
| `build_exe.bat` | Fallback — CMD batch build script |
| `build_Key_exe.bat` | Builds only the KeyGen tool |
| `identity_manager.spec` | PyInstaller config for main app |
| `IDManager_KeyGen.spec` | PyInstaller config for KeyGen tool |
| `requirements.txt` | Python package list |
| `README.md` | This file |

---

## Quick Start — Build the EXE (do this ONCE on a build machine)

> **Python is only needed on the BUILD machine.**
> The resulting `.exe` files run on any Windows machine with NO Python required.

### Option A — PowerShell ✅ Recommended

```powershell
# 1. Open PowerShell as Administrator (right-click Start → Windows PowerShell (Admin))
# 2. Navigate to this folder
cd C:\IDManager-Build

# 3. Allow script execution for this session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 4. Run the build
.\build_exe.ps1
```

The script will automatically:
- Check for Python 3.8+ (silently installs Python 3.11 if not found)
- Install all packages: `ldap3`, `openpyxl`, `reportlab`, `Pillow`, `pyinstaller`
- Build `dist\IdentityManager.exe` (~40–70 MB, GUI, no console window)
- Build `dist\IDManager_KeyGen.exe` (~8 MB, console, key generation tool)
- Open `dist\` folder when complete

---

### Option B — CMD Batch (Fallback)

```cmd
cd C:\IDManager-Build
build_exe.bat
```

---

### Option C — Manual PyInstaller

```cmd
pip install ldap3 openpyxl reportlab Pillow pyinstaller
pyinstaller identity_manager.spec --clean --noconfirm
pyinstaller IDManager_KeyGen.spec --clean --noconfirm
```

---

## System Requirements

### Build Machine (one-time only)
| Item | Requirement |
|---|---|
| OS | Windows 10 / Server 2016 or later (64-bit) |
| Python | 3.8 or later (script auto-installs 3.11 if missing) |
| Internet | Required to download packages |
| Disk space | ~500 MB free |
| PowerShell | 5.x or later |

### Target Machines (where you deploy IdentityManager.exe)
| Item | Requirement |
|---|---|
| OS | Windows Server 2016 / 2019 / 2022 **or** Windows 10 / 11 (64-bit) |
| Python | ❌ NOT required — bundled inside the EXE |
| Network | Port 389 (LDAP) or 636 (LDAPS) to your Domain Controller |
| Disk | ~70 MB free |
| RAM | 256 MB minimum (512 MB recommended) |

---

## Deploying IdentityManager.exe

After building, copy **only** `dist\IdentityManager.exe` to target machines:

```
dist\
  IdentityManager.exe      ← copy this to servers / network share
  IDManager_KeyGen.exe     ← keep on admin machine ONLY
```

| Method | Steps |
|---|---|
| Single server | Copy to `C:\Tools\` → create Desktop shortcut |
| Network share | Copy to `\\server\share\Tools\` → staff double-click UNC path |
| Group Policy | Deploy via GPO Software Installation |
| SCCM / Intune | Package as a portable app — no MSI needed |
| USB | Copy to USB → run directly, no install required |

---

## First Launch on Target Machine

1. Double-click `IdentityManager.exe`
2. **Windows SmartScreen** may appear on first run → click **More info → Run anyway** (one-time prompt for unsigned EXEs)
3. The Enhanced Login window opens automatically
4. Fill in AD connection details:

| Field | Example |
|---|---|
| AD Server | `dc01.contoso.com` |
| Port | `389` (LDAP, default) or `636` (LDAPS) |
| Base DN | `DC=contoso,DC=com` |
| Username | `admin@contoso.com` |
| Password | Your AD admin password |

5. Click **🔗 Connect to AD**
6. OUs, Groups, and Users load automatically

> **Demo Mode:** Click **🧪 Demo Mode** on the login screen to explore without a real AD connection.

---

## Activation

After first launch:

1. Go to **Help → Activate Software…**
2. Enter your activation code (format: `IDP-DAYS-XXXXXXXXXXXXXXXX-YYYYYYYY`)
3. Contact ITProAcademy.co.in if you need a code

### Generating Activation Codes (admin only)

Use `IDManager_KeyGen.exe` on your **admin machine only**:

```cmd
IDManager_KeyGen.exe                     # interactive menu
IDManager_KeyGen.exe --days 365          # 1-year code
IDManager_KeyGen.exe --months 6          # 6-month code
IDManager_KeyGen.exe --verify IDP-...    # verify a code
```

---

## Antivirus / Windows Defender

PyInstaller EXEs bundle a Python runtime and are sometimes flagged as "unknown" by AV. This is a **false positive** — the EXE is built entirely from your own source code.

To resolve:
- Add `IdentityManager.exe` to your AV exclusion list on each target machine
- Or sign the EXE with a code-signing certificate for enterprise environments
- On first run, click **More info → Run anyway** in Windows SmartScreen

---

## LDAP / LDAPS Notes

| Mode | Port | Notes |
|---|---|---|
| Plain LDAP | 389 | Default. Passwords set via 4-method cascade |
| LDAPS (SSL) | 636 | Full encryption. Requires DC certificate |

Password set method order (tried automatically):
1. `unicodePwd` on existing connection (instant if LDAPS)
2. Extended Password Modify operation (most DCs, plain LDAP)
3. Fresh LDAPS connection on port 636
4. StartTLS upgrade on port 389

If all 4 fail → account created **disabled** → set password manually in ADUC.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Build fails — "Access Denied" | Run PowerShell/CMD **as Administrator** |
| AV deletes EXE during build | Add build folder to AV exclusions before running |
| "Python not found" | Install Python 3.11 from python.org — tick "Add to PATH" |
| App won't connect to AD | Check firewall allows port 389/636 to the DC |
| LDAPS fails | Uncheck SSL, use port 389 — passwords use StartTLS automatically |
| Password cannot be set | Open port 636 on DC firewall, or set password manually in ADUC |
| SmartScreen blocks EXE | Click "More info" → "Run anyway" (first run only) |
| EXE crashes on launch | Run from CMD window to see error: `IdentityManager.exe` |
| EXE is large (~60 MB) | Normal — bundles Python runtime + all libraries |
| Activation code rejected | Each code is single-use per machine. Contact ITProAcademy.co.in |

---

## Optional: Custom Icon

1. Place a `256×256` pixel `.ico` file named `icon.ico` in this folder
2. Open `identity_manager.spec` and uncomment the icon line:
   ```python
   # icon='icon.ico',   →   icon='icon.ico',
   ```
3. Re-run `build_exe.ps1`

---

## Config File Locations (on target machine)

| File | Purpose |
|---|---|
| `%USERPROFILE%\.idmanager_config.json` | Connection settings, activation status |
| `%USERPROFILE%\.idmanager_stats.json` | Audit log, operation counters |
| `%USERPROFILE%\.idmanager_logo.dat` | Company logo (if uploaded) |

---

## Package Versions

```
ldap3 >= 2.9.1         Active Directory LDAP/LDAPS connectivity
openpyxl >= 3.1.0      Excel (.xlsx) report export
reportlab >= 4.0.0     PDF report export
Pillow >= 10.0.0       Company logo upload & display
pyinstaller >= 6.0.0   Single-file portable EXE packaging
```

---

**ITProAcademy.co.in** | Identity Manager v1.0 | © 2024
