"""Leitura de metadados de executáveis (VERSIONINFO) via API nativa do Windows.
Somente leitura. Em outros sistemas devolve vazio (permite testar a lógica fora do Windows)."""
from __future__ import annotations
import os
import struct
from functools import lru_cache
from .models import FileMeta

_KEYS = {
    "CompanyName": "company",
    "FileDescription": "description",
    "ProductName": "product",
    "FileVersion": "version",
    "OriginalFilename": "original_name",
}


@lru_cache(maxsize=2048)
def read_file_meta(path: str) -> FileMeta:
    if os.name != "nt" or not path:
        return FileMeta()
    try:
        import ctypes
        from ctypes import wintypes

        ver = ctypes.WinDLL("version", use_last_error=True)
        ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        ver.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        ver.GetFileVersionInfoW.restype = wintypes.BOOL
        ver.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                       ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
        ver.VerQueryValueW.restype = wintypes.BOOL

        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return FileMeta()
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return FileMeta()

        ptr, length = ctypes.c_void_p(), wintypes.UINT()
        if not ver.VerQueryValueW(buf, r"\VarFileInfo\Translation", ctypes.byref(ptr), ctypes.byref(length)) \
                or length.value < 4:
            return FileMeta()
        lang, codepage = struct.unpack("<HH", ctypes.string_at(ptr.value, 4))

        out = {}
        for key, field_name in _KEYS.items():
            sub = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\{key}"
            if ver.VerQueryValueW(buf, sub, ctypes.byref(ptr), ctypes.byref(length)) and length.value:
                text = ctypes.wstring_at(ptr.value, length.value).rstrip("\x00").strip()
                if text:
                    out[field_name] = text
        return FileMeta(**out)
    except Exception:
        return FileMeta()
def is_admin() -> bool:
    """True se o programa está rodando como administrador. Somente leitura."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False