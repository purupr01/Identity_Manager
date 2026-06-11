# -*- mode: python ; coding: utf-8 -*-
# ============================================================
#  Identity Manager — PyInstaller Spec
#  ITProAcademy.co.in
#
#  DEPLOYMENT MODEL: --onedir  (folder, not single EXE)
#  ─────────────────────────────────────────────────────────
#  WHY NOT --onefile?
#  The --onefile mode bundles everything into one EXE that
#  self-extracts to %TEMP% on every launch.  Windows Defender
#  and most enterprise EDR products flag this behaviour as
#  malware (Trojan dropper pattern) and quarantine the file,
#  generating security tickets.
#
#  The --onedir mode produces a folder (dist\IdentityManager\)
#  containing IdentityManager.exe + DLLs/PYDs alongside it.
#  No runtime extraction occurs — Defender sees a normal
#  application folder, not a self-extracting dropper.
#
#  DEPLOYMENT:
#    Copy the entire dist\IdentityManager\ folder to the
#    target machine (e.g. C:\Tools\IdentityManager\).
#    Run IdentityManager.exe from inside that folder.
#    Optionally create a Desktop shortcut pointing to it.
#    Add the folder to AV exclusions (one exclusion covers all).
# ============================================================

block_cipher = None

a = Analysis(
    ['identity_manager.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'ldap3',
        'ldap3.core',
        'ldap3.core.exceptions',
        'ldap3.protocol',
        'ldap3.protocol.rfc4511',
        'ldap3.protocol.microsoft',
        'ldap3.extend',
        'ldap3.extend.microsoft',
        'ldap3.extend.microsoft.modifyPassword',
        'ldap3.utils',
        'ldap3.abstract',
        'ldap3.abstract.entry',
        'openpyxl',
        'openpyxl.styles',
        'openpyxl.utils',
        'reportlab',
        'reportlab.lib',
        'reportlab.lib.pagesizes',
        'reportlab.lib.styles',
        'reportlab.lib.colors',
        'reportlab.lib.units',
        'reportlab.platypus',
        'reportlab.platypus.tables',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.filedialog',
        'tkinter.scrolledtext',
        'ssl',
        'hashlib',
        'threading',
        'json',
        'datetime',
        're',
        'os',
        'pathlib',
        'base64',
        'string',
        'secrets',
        'io',
        'socket',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'scipy',
        'pandas',
        'pytest',
        'IPython',
        'jupyter',
        'notebook',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],                         # ← onedir: binaries/datas go into COLLECT, not EXE
    exclude_binaries=True,      # ← required for onedir mode
    name='IdentityManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                  # ← UPX compression also triggers AV; disabled
    console=False,              # GUI app — no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='icon.ico',          # Uncomment + place icon.ico here for custom icon
)

# COLLECT assembles the folder: EXE + all DLLs/PYDs/data files
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,                  # UPX disabled — triggers AV heuristics
    upx_exclude=[],
    name='IdentityManager',     # → dist\IdentityManager\ folder
)
