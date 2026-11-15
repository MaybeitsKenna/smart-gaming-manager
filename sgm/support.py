"""Etapa 10: informações para suporte e limpeza de dados pessoais. SOMENTE LEITURA.
O texto gerado NÃO inclui nomes de programas, caminhos de arquivos nem o nome de usuário do Windows."""
from __future__ import annotations
import getpass
import os
import platform
import re
import sys
from collections import Counter
from typing import Optional

import psutil

from . import __version__
from .classifier import Category
from .gaming import detect_emulators
from .service import AnalysisResult
from .winmeta import is_admin


def sanitize(text: str) -> str:
    """Troca a pasta do usuário, o nome do usuário e o nome do computador por marcadores."""
    out = text
    home = os.path.expanduser("~")
    if home and home != "~":
        out = re.sub(re.escape(home), "~", out, flags=re.IGNORECASE)
    for value, marker in ((getpass.getuser(), "<usuario>"), (platform.node(), "<computador>")):
        if value and len(value) >= 3:
            out = re.sub(re.escape(value), marker, out, flags=re.IGNORECASE)
    return out


def _windows_label() -> str:
    try:
        build = sys.getwindowsversion().build          # type: ignore[attr-defined]
    except Exception:
        return platform.platform()
    return f"{'Windows 11' if build >= 22000 else 'Windows 10'} (build {build})"


def build_support_info(result: Optional[AnalysisResult], actions_count: int = 0) -> str:
    vm = psutil.virtual_memory()
    L = ["SMART GAMING MANAGER - INFORMAÇÕES PARA SUPORTE",
         "(sem nomes de programas, caminhos de arquivos ou nome de usuário)", "",
         f"Programa            : v{__version__}",
         f"Executável (.exe)   : {'sim' if getattr(sys, 'frozen', False) else 'não (rodando pelo Python)'}",
         f"Sistema             : {_windows_label()}",
         f"Python              : {platform.python_version()}",
         f"Processador         : {psutil.cpu_count(logical=False) or '?'} núcleos físicos / "
         f"{psutil.cpu_count(logical=True) or '?'} lógicos",
         f"Memória RAM total   : {vm.total / 1024 ** 3:.1f} GB",
         f"Como administrador  : {'sim' if is_admin() else 'não'}", ""]
    if result is None:
        L.append("Análise             : ainda não foi feita")
        return "\n".join(L)

    counts = Counter(c.category for c in result.classifications.values())
    suspects = sum(1 for c in result.classifications.values() if "suspect" in c.tags)
    closable = sum(1 for g in result.groups if g.can_close)
    emus = [e for e in detect_emulators(result.snapshot, result.classifications) if not e.auxiliary]
    sig = "OK" if not result.signature_error else "FALHOU: " + sanitize(result.signature_error)[:200]
    L += [f"Verif. assinaturas  : {sig}",
          f"Processos           : {result.snapshot.process_count}  |  aplicativos (grupos): {len(result.groups)}",
          "Por categoria       : " + "  ".join(f"{cat.value} {counts.get(cat, 0)}" for cat in Category),
          f"Marcados suspeitos  : {suspects}",
          f"Aplicativos encerráveis: {closable}",
          "Emulador detectado  : " + (", ".join(f"{e.label} ({e.process_count} processos)" for e in emus)
                                      if emus else "nenhum"),
          f"Encerrados na sessão: {actions_count}"]
    return "\n".join(L)