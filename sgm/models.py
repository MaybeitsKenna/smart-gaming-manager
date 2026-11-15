from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class FileMeta:
    """Metadados lidos do próprio executável (somente leitura)."""
    company: Optional[str] = None
    description: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    original_name: Optional[str] = None


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe_path: Optional[str]            # None = sem acesso ao caminho (tratar como suspeito de proteção)
    cmdline_available: bool
    username: Optional[str]
    parent_pid: Optional[int]
    parent_name: Optional[str]
    create_time: Optional[float]
    cpu_percent: float                 # normalizado: 0-100 do total da máquina
    ram_mb: float                      # working set (RSS)
    has_window: bool = False           # preenchido em etapa posterior (aplicativo vs. segundo plano)
    meta: FileMeta = field(default_factory=FileMeta)
    access_denied: bool = False        # True se faltou permissão para ler algum dado


@dataclass
class SystemSnapshot:
    cpu_total_percent: float
    ram_total_mb: float
    ram_used_mb: float
    ram_available_mb: float
    process_count: int
    processes: list[ProcessInfo]
    