"""Lê (SOMENTE LEITURA) quais programas iniciam junto com o Windows pelas chaves 'Run' do Registro.
Nada é criado, alterado ou apagado."""
from __future__ import annotations
import os
import re
from .signature import norm_path

_RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def _extract_exe(command: str) -> str:
    command = os.path.expandvars(command.strip())
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end > 0 else command[1:]
    m = re.match(r"(.+?\.exe)\b", command, re.IGNORECASE)
    return m.group(1) if m else command.split(" ")[0]


def read_startup_paths() -> set[str]:
    """Conjunto de caminhos (normalizados) de executáveis que iniciam com o Windows."""
    if os.name != "nt":
        return set()
    import winreg
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    found: set[str] = set()
    for hive_name, subkey in _RUN_KEYS:
        try:
            with winreg.OpenKey(hives[hive_name], subkey, 0, winreg.KEY_READ) as key:   # KEY_READ = só leitura
                i = 0
                while True:
                    try:
                        _name, value, _type = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    if isinstance(value, str) and value.strip():
                        found.add(norm_path(_extract_exe(value)))
                    i += 1
        except OSError:
            continue
    return found