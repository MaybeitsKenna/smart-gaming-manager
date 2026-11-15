"""Etapa 6: encerramento individual e seguro.

Fluxo, sempre por aplicativo (nunca em massa):
  1) REVALIDA no instante do clique: o processo ainda existe? é o mesmo (hora de criação)? mesmo arquivo?
  2) TRAVAS INDEPENDENTES do classificador (defesa em camadas): nunca processos do Windows, de segurança,
     do emulador/jogo, deste programa ou do terminal dele.
  3) PEDIDO NORMAL: envia "fechar" às janelas (como clicar no X). No Windows, terminate() do psutil é o mesmo
     que kill(), então o pedido normal é feito pelas janelas (WM_CLOSE).
  4) FORÇAR só existe como segunda etapa, depois de o usuário ver que o pedido normal não funcionou.
Não altera Registro, serviços, drivers, prioridades nem apaga arquivos."""
from __future__ import annotations
import os
import time
from dataclasses import dataclass, field

import psutil

from .classifier import CORE_WINDOWS_NAMES, SYSTEM_ROOT, Category, _emulator_hit
from .knowledge import AppGroup
from .models import ProcessInfo, SystemSnapshot
from .signature import norm_path

NEVER_KILL = set(CORE_WINDOWS_NAMES) | {
    "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe", "mpcmdrun.exe", "securityhealthhost.exe",
}
WM_CLOSE = 0x0010
# Marcas que o classificador usa para proteger. Se o grupo traz qualquer uma, o encerramento é recusado.
PROTECTIVE_TAGS = {"emulator", "audio", "network", "driver", "security", "input", "self", "windows", "system",
                   "suspect"}


@dataclass
class Target:
    info: ProcessInfo
    proc: psutil.Process


@dataclass
class Plan:
    group: AppGroup
    targets: list[Target] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    blocked: str = ""                      # se preenchido, NADA será encerrado


@dataclass
class Outcome:
    method: str                            # "normal" ou "forçado"
    closed: list[int] = field(default_factory=list)
    still_running: list[int] = field(default_factory=list)
    denied: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    windows_signaled: int = 0


@dataclass
class ActionRecord:
    name: str
    method: str
    closed_count: int
    ram_mb: float
    cpu_percent: float
    when: float
    what: str = ""
    side_effects: str = ""


def _under_system(path: str) -> bool:
    return norm_path(path).startswith(SYSTEM_ROOT.rstrip("\\") + "\\")


def own_pids() -> set[int]:
    """Este programa + toda a cadeia de pais (terminal, VS Code etc.), recalculado a cada uso."""
    pids = {os.getpid()}
    try:
        pids.update(p.pid for p in psutil.Process().parents())
    except psutil.Error:
        pass
    return pids


def current_user() -> str:
    try:
        return psutil.Process().username().lower()
    except psutil.Error:
        return ""


def prepare(group: AppGroup, own: set[int] | None = None, me: str | None = None) -> Plan:
    """Revalida tudo agora. Qualquer dúvida => bloqueia."""
    own = own_pids() if own is None else own
    me = current_user() if me is None else me.lower()
    plan = Plan(group=group)

    if not group.can_close or group.category not in (Category.SEGURO, Category.ATENCAO):
        plan.blocked = ("Este aplicativo é protegido, desconhecido ou tem processos protegidos misturados. "
                        "Não pode ser encerrado por este programa.")
        return plan
    if group.key.startswith("sem-caminho"):
        plan.blocked = "O caminho do executável não pôde ser verificado."
        return plan
    bad_tags = sorted(group.tags & PROTECTIVE_TAGS)
    if bad_tags:
        plan.blocked = f"Bloqueado por segurança: o aplicativo foi marcado como {', '.join(bad_tags)}."
        return plan

    # Travas independentes do classificador
    for info in group.members:
        reason = None
        if not me or not info.username or info.username.lower() != me:
            reason = "pertence ao sistema, a um serviço ou a outro usuário"
        elif info.access_denied or not info.exe_path:
            reason = "os dados do processo não puderam ser lidos"
        elif info.name.lower() in NEVER_KILL:
            reason = "processo essencial do Windows ou de segurança"
        elif info.pid in own:
            reason = "faz parte deste programa ou do terminal em que ele roda"
        elif info.exe_path and _under_system(info.exe_path):
            reason = "arquivo na pasta do Windows"
        elif _emulator_hit(info):
            reason = "relacionado ao emulador Android ou ao jogo"
        if reason:
            plan.blocked = f"Bloqueado por segurança ({info.name}, PID {info.pid}): {reason}."
            return plan

    # Revalidação: o processo ainda é o mesmo?
    for info in group.members:
        try:
            proc = psutil.Process(info.pid)
            # No Windows, um processo já encerrado ainda pode ser "aberto" enquanto alguém segura um acesso a ele.
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                plan.skipped.append(f"PID {info.pid}: já tinha sido encerrado.")
                continue
            if info.create_time is not None and abs(proc.create_time() - info.create_time) > 1.0:
                plan.skipped.append(f"PID {info.pid}: o número agora pertence a outro programa (ignorado).")
                continue
            exe = proc.exe()
            if not exe or norm_path(exe) != group.key:
                plan.skipped.append(f"PID {info.pid}: o arquivo executável mudou (ignorado).")
                continue
            if proc.username().lower() != me:
                plan.skipped.append(f"PID {info.pid}: agora pertence a outro usuário (ignorado).")
                continue
            plan.targets.append(Target(info, proc))
        except psutil.NoSuchProcess:
            plan.skipped.append(f"PID {info.pid}: já tinha sido encerrado.")
        except psutil.Error:
            plan.skipped.append(f"PID {info.pid}: não foi possível verificar (ignorado).")

    if not plan.targets:
        plan.blocked = "Nenhum processo deste aplicativo está mais em execução, ou não puderam ser verificados."
    return plan


def _post_wm_close(pids: set[int]) -> int:
    """Pede a cada janela visível dos processos que feche (equivale a clicar no X). Retorna quantas."""
    if os.name != "nt":
        return 0
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [enum_proc, wintypes.LPARAM]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

    count = 0

    def callback(hwnd, _lparam):
        nonlocal count
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value in pids and user32.IsWindowVisible(hwnd):
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
            count += 1
        return True

    cb = enum_proc(callback)
    user32.EnumWindows(cb, 0)
    return count


def close_gracefully(plan: Plan, wait_seconds: float = 8.0) -> Outcome:
    out = Outcome(method="normal")
    if not plan.targets:
        return out
    pids = {t.proc.pid for t in plan.targets}
    out.windows_signaled = _post_wm_close(pids)
    procs = [t.proc for t in plan.targets]
    gone, alive = psutil.wait_procs(procs, timeout=wait_seconds if out.windows_signaled else 0)
    out.closed = [p.pid for p in gone]
    out.still_running = [p.pid for p in alive]
    return out


def force_kill(plan: Plan) -> Outcome:
    out = Outcome(method="forçado")
    killable = []
    for t in plan.targets:
        try:
            t.proc.kill()
            killable.append(t.proc)
        except psutil.NoSuchProcess:
            out.closed.append(t.proc.pid)
        except psutil.AccessDenied:
            out.denied.append(t.proc.pid)
        except psutil.Error as exc:
            out.errors.append(f"PID {t.proc.pid}: {exc}")
    gone, alive = psutil.wait_procs(killable, timeout=4)
    out.closed += [p.pid for p in gone]
    out.still_running = [p.pid for p in alive] + out.denied
    return out


def make_record(plan: Plan, out: Outcome) -> ActionRecord:
    closed = set(out.closed)
    freed = [t.info for t in plan.targets if t.proc.pid in closed]
    ex = plan.group.explanation
    return ActionRecord(plan.group.name, out.method, len(closed), round(sum(i.ram_mb for i in freed), 1),
                        round(sum(i.cpu_percent for i in freed), 1), time.time(), ex.what, ex.side_effects)


def dependents(group: AppGroup, snapshot: SystemSnapshot) -> list[str]:
    """Outros processos (de fora do grupo) que foram iniciados por este aplicativo."""
    mine = set(group.pids)
    return sorted({p.name for p in snapshot.processes if p.parent_pid in mine and p.pid not in mine})


def confirmation_text(group: AppGroup, deps: list[str]) -> str:
    e = group.explanation
    n = len(group.members)
    lines = [
        f"Aplicativo a encerrar : {group.name}" + (f"  ({n} processos)" if n > 1 else ""),
        f"O que faz             : {e.what}",
        f"Consumo agora         : {e.consumption}",
        "",
        "O que pode deixar de funcionar:",
        f"  {e.side_effects or 'Apenas o próprio aplicativo deixa de funcionar até você abri-lo de novo.'}",
        "",
        "Pode afetar outros aplicativos?",
    ]
    if deps:
        shown = ", ".join(deps[:12]) + ("..." if len(deps) > 12 else "")
        lines.append(f"  Estes processos foram iniciados por ele e podem fechar junto: {shown}.")
    else:
        lines.append("  Nenhum outro processo foi identificado como iniciado por ele.")
    lines += [
        "",
        "Como será feito:",
        "  1) Um pedido normal para fechar (como clicar no X da janela). Nada é forçado agora.",
        "  2) Se ele não fechar, você decide se quer forçar. Forçar pode perder dados não salvos.",
        "",
        "Depois de fechado, você pode abrir o aplicativo de novo normalmente.",
        "Nada é desinstalado, apagado ou alterado no Windows.",
    ]
    return "\n".join(lines)
