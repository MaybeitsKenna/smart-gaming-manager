"""Camada de serviço: junta escaneamento + assinaturas + classificação + explicações.
Usada pela interface. SOMENTE LEITURA."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional

from . import signature
from .classifier import Classification, classify_all
from .knowledge import AppGroup, build_groups
from .models import SystemSnapshot
from .scanner import scan_system
from .signature import verify_signatures
from .startup import read_startup_paths


@dataclass
class AnalysisResult:
    snapshot: SystemSnapshot
    classifications: dict[int, Classification]
    groups: list[AppGroup]
    signature_error: str = ""


def analyze(progress: Optional[Callable[[str], None]] = None) -> AnalysisResult:
    def say(msg: str) -> None:
        if progress:
            progress(msg)

    say("Lendo processos e medindo CPU e RAM...")
    snap = scan_system()
    say("Verificando assinaturas digitais (pode levar alguns segundos)...")
    sigs = verify_signatures({p.exe_path for p in snap.processes if p.exe_path})
    sig_error = "" if sigs else (signature.LAST_ERROR or "Não foi possível verificar assinaturas.")
    say("Classificando e explicando...")
    startup = read_startup_paths()
    cls = classify_all(snap.processes, sigs, startup)
    groups = build_groups(snap.processes, cls)
    return AnalysisResult(snap, cls, groups, sig_error)