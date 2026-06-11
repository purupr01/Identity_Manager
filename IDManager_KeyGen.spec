# -*- mode: python ; coding: utf-8 -*-
# ============================================================
#  IDManager KeyGen — PyInstaller Spec
#  ITProAcademy.co.in
#  Builds a single-file console EXE for activation key generation
# ============================================================

block_cipher = None

a = Analysis(
    ['generate_activation.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'hashlib',
        'datetime',
        'argparse',
        'sys',
        'secrets',
        'string',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='IDManager_KeyGen',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,           # Console app — shows output in CMD window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
