"""Regras que NUNCA podem ser quebradas pela classificação. Usadas pelos testes e pela auditoria no seu PC.
Somente leitura: apenas olha os resultados da análise e devolve uma lista de violações (vazia = tudo certo)."""
from __future__ import annotations

from .classifier import (CORE_WINDOWS_NAMES, KNOWN_OPTIONAL, SYSTEM_ROOT, WINDOWSAPPS_ROOT, Category,
                         Classification, _audio_net_hit, _emulator_hit, _under)
from .models import ProcessInfo

CLOSABLE = (Category.SEGURO, Category.ATENCAO)
BLOCKING_TAGS = {"suspect", "self", "system", "windows", "driver", "security", "input", "emulator", "audio", "network"}


def violations(processes: list[ProcessInfo], cls: dict[int, Classification], me: str) -> list[str]:
    me = (me or "").lower()
    by_pid = {p.pid: p for p in processes}
    out: list[str] = []
    for p in processes:
        c = cls[p.pid]
        if c.category not in CLOSABLE:
            continue
        name, path, who = p.name.lower(), p.exe_path, f"{p.name} (PID {p.pid})"
        if not path or p.access_denied:
            out.append(f"{who}: encerrável, mas sem caminho legível")
        if not p.username or p.username.lower() != me:
            out.append(f"{who}: encerrável, mas pertence a outro usuário/sistema ({p.username})")
        if path and _under(path, SYSTEM_ROOT):
            out.append(f"{who}: encerrável, mas está na pasta do Windows")
        if name in CORE_WINDOWS_NAMES:
            out.append(f"{who}: encerrável, mas tem nome de processo essencial do Windows")
        if _emulator_hit(p):
            out.append(f"{who}: encerrável, mas parece ser do emulador/jogo")
        if _audio_net_hit(p):
            out.append(f"{who}: encerrável, mas parece ser de áudio/rede")
        bad = c.tags & BLOCKING_TAGS
        if bad:
            out.append(f"{who}: encerrável, mas tem marcas de proteção {sorted(bad)}")
        if c.category == Category.SEGURO and not (name in KNOWN_OPTIONAL and c.sig_status == "Valid"):
            out.append(f"{who}: SEGURO sem ser app conhecido com assinatura válida")
        if c.category == Category.ATENCAO and not (
                c.sig_status == "Valid"
                or (c.sig_status == "NotSigned" and path and _under(path, WINDOWSAPPS_ROOT))):
            out.append(f"{who}: ATENÇÃO sem assinatura válida (status {c.sig_status})")
        parent = by_pid.get(p.parent_pid) if p.parent_pid is not None else None
        if parent and "emulator" in cls[parent.pid].tags:
            out.append(f"{who}: encerrável, mas é filho de processo do emulador")
    return out
