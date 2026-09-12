# -*- mode: python ; coding: utf-8 -*-
import sys
from PyInstaller.utils.hooks import collect_data_files

hiddenimports = [
    "webview",
    "Crypto",
    "Crypto.Cipher",
    "Crypto.Cipher.AES",
    "Crypto.Protocol.KDF",
    "Crypto.Hash",
    "Crypto.Hash.SHA256",
    "Crypto.Random",
    "websocket",
    "requests",
]
if sys.platform == "darwin":
    hiddenimports.append("webview.platforms.cocoa")
elif sys.platform == "win32":
    hiddenimports.extend(["webview.platforms.edgechromium", "webview.platforms.winforms"])
else:
    hiddenimports.append("webview.platforms.gtk")

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[("ui", "ui"), ("sealed.example.json", ".")] + collect_data_files("webview"),
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "hypothesis"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Sealed",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
)
