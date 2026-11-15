"""Etapa 2: coleta de processos e métricas. NÃO classifica e NÃO encerra nada."""
from __future__ import annotations
import time
import psutil
from .models import ProcessInfo, SystemSnapshot
from .winmeta import read_file_meta

MB = 1024 * 1024


def _safe(fn, default=None):
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return default


def scan_system(sample_seconds: float = 1.0) -> SystemSnapshot:
    """Mede CPU durante `sample_seconds` (psutil precisa de duas leituras para calcular %)."""
    ncpu = psutil.cpu_count(logical=True) or 1

    procs = list(psutil.process_iter())
    for p in procs:                                   # 1ª leitura (prime)
        _safe(lambda p=p: p.cpu_percent(None))
    psutil.cpu_percent(None)
    time.sleep(sample_seconds)
    cpu_total = psutil.cpu_percent(None)

    infos: list[ProcessInfo] = []
    names: dict[int, str] = {}
    for p in procs:
        names[p.pid] = _safe(p.name, "?")

    for p in procs:
        denied = False
        with p.oneshot():
            exe = _safe(p.exe)
            if not exe:
                denied = True
            cpu = _safe(lambda: p.cpu_percent(None), 0.0) / ncpu   # normaliza para 0-100 do total
            mem = _safe(lambda: p.memory_info().rss, 0) / MB
            ppid = _safe(p.ppid)
            infos.append(ProcessInfo(
                pid=p.pid,
                name=names.get(p.pid, "?"),
                exe_path=exe or None,
                cmdline_available=_safe(p.cmdline) is not None,
                username=_safe(p.username),
                parent_pid=ppid,
                parent_name=names.get(ppid) if ppid is not None else None,
                create_time=_safe(p.create_time),
                cpu_percent=round(cpu, 1),
                ram_mb=round(mem, 1),
                meta=read_file_meta(exe) if exe else read_file_meta(""),
                access_denied=denied,
            ))

    vm = psutil.virtual_memory()
    return SystemSnapshot(
        cpu_total_percent=cpu_total,
        ram_total_mb=round(vm.total / MB),
        ram_used_mb=round((vm.total - vm.available) / MB),
        ram_available_mb=round(vm.available / MB),
        process_count=len(infos),
        processes=sorted(infos, key=lambda i: i.ram_mb, reverse=True),
    )
