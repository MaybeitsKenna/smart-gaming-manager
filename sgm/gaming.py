"""Etapa 7: Gaming Mode. SOMENTE LEITURA e apresentação: não encerra nada.

- Identifica o(s) emulador(es) Android em execução (não assume um nome fixo de processo).
- Resume o que está protegido automaticamente (emulador/jogo, áudio, rede, drivers, segurança...).
- Lista só os aplicativos opcionais que estão consumindo recursos.
- Monta o resumo "antes e agora" da sessão.
O encerramento continua sendo feito um por um, pelo fluxo da Etapa 6."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .classifier import Category, Classification
from .knowledge import AppGroup, _impact
from .models import ProcessInfo, SystemSnapshot
from .terminator import ActionRecord

# (rótulo, trechos do caminho/empresa/produto/descrição). A ordem importa: o mais específico primeiro.
EMULATOR_FAMILIES = [
    ("MSI App Player / BlueStacks", ("msi app player", "msiappplayer", "bluestacks", "bstk", "hd-player", "hd-adb")),
    ("LDPlayer", ("ldplayer", "ldmultiplayer", "dnplayer", "ldvbox")),
    ("MEmu", ("memu", "microvirt")),
    ("NoxPlayer", ("bignox", "noxplayer")),
    ("GameLoop (Tencent)", ("gameloop", "tencent gaming", "aow_exe", "tgp_daemon", "txgameassistant",
                             "androidemulator")),
    ("Genymotion", ("genymotion",)),
    ("Windows Subsystem for Android", ("wsaclient", "subsystem for android")),
    ("Android Emulator (QEMU)", ("qemu-system",)),
    ("SmartGaGa / KOPlayer", ("smartgaga", "koplayer")),
    ("VirtualBox (base de alguns emuladores)", ("virtualbox", "vboxheadless", "vboxsvc")),
    ("ADB (ponte do Android)", ("adb.exe", "android debug bridge")),
]
EXACT_NAMES = {"nox.exe": "NoxPlayer", "noxvmhandle.exe": "NoxPlayer", "nox_adb.exe": "NoxPlayer",
               "adb.exe": "ADB (ponte do Android)"}
AUXILIARY = {"ADB (ponte do Android)", "VirtualBox (base de alguns emuladores)"}
GAME_KEYS = ("free fire", "freefire", "garena")

BUCKETS = [
    ("emulator", "emulador/jogo"), ("audio", "áudio"), ("network", "rede"), ("input", "teclado/mouse/controle"),
    ("security", "antivírus/Defender"), ("driver", "drivers e periféricos"), ("self", "este programa e o terminal dele"),
    ("windows", "componentes do Windows"), ("system", "serviços e núcleo do sistema"),
]


@dataclass
class EmulatorInfo:
    label: str
    exes: list[str]
    process_count: int
    ram_mb: float
    cpu_percent: float
    auxiliary: bool


@dataclass
class GamingSession:
    started: float
    before_cpu: float
    before_used_mb: float
    before_avail_mb: float
    actions_start: int


def _blob(p: ProcessInfo) -> str:
    return " ".join(filter(None, [p.exe_path, p.name, p.meta.company, p.meta.product, p.meta.description])).lower()


def _family_or_none(p: ProcessInfo) -> Optional[str]:
    name = p.name.lower()
    if name in EXACT_NAMES:
        return EXACT_NAMES[name]
    blob = _blob(p)
    for label, keys in EMULATOR_FAMILIES:
        if any(k in blob for k in keys):
            return label
    return None


def detect_emulators(snapshot: SystemSnapshot, cls: dict[int, Classification]) -> list[EmulatorInfo]:
    procs = [p for p in snapshot.processes if "emulator" in cls[p.pid].tags]
    by_pid = {p.pid: p for p in procs}
    labels: dict[int, str] = {}
    for p in procs:
        labels[p.pid] = _family_or_none(p) or ""
    for _ in range(4):                                   # filhos herdam a família do pai
        for p in procs:
            if not labels[p.pid] and p.parent_pid in labels and labels[p.parent_pid]:
                labels[p.pid] = labels[p.parent_pid]
    families: dict[str, list[ProcessInfo]] = {}
    for p in procs:
        families.setdefault(labels[p.pid] or "Emulador Android (não identificado pelo nome)", []).append(p)
    result = []
    for label, members in families.items():
        exes = sorted({m.name for m in members})
        result.append(EmulatorInfo(label, exes, len(members), round(sum(m.ram_mb for m in members), 1),
                                   round(sum(m.cpu_percent for m in members), 1), label in AUXILIARY))
    result.sort(key=lambda e: e.ram_mb, reverse=True)
    return result


def protection_summary(snapshot: SystemSnapshot, cls: dict[int, Classification]) -> list[tuple[str, int, float]]:
    counts: dict[str, list] = {label: [0, 0.0] for _, label in BUCKETS}
    counts["outros protegidos"] = [0, 0.0]
    for p in snapshot.processes:
        c = cls[p.pid]
        if c.category != Category.PROTEGIDO:
            continue
        label = next((lab for tag, lab in BUCKETS if tag in c.tags), "outros protegidos")
        counts[label][0] += 1
        counts[label][1] += p.ram_mb
    return [(label, n, round(ram, 1)) for label, (n, ram) in counts.items() if n]


def mixed_protected_names(groups: list[AppGroup]) -> list[str]:
    return sorted(g.name for g in groups if g.mixed and not g.can_close)


def candidates(groups: list[AppGroup], min_ram: float = 100.0, min_cpu: float = 0.5) -> list[AppGroup]:
    """Aplicativos opcionais (SEGURO/ATENÇÃO) que estão consumindo recursos de forma relevante."""
    rank = {"ALTO": 3, "MÉDIO": 2, "BAIXO": 1}
    found = [g for g in groups if g.can_close and (g.ram_mb >= min_ram or g.cpu_percent >= min_cpu)]
    found.sort(key=lambda g: (rank[_impact(g.ram_mb, g.cpu_percent)], g.cpu_percent, g.ram_mb), reverse=True)
    return found


# ---------------------------------------------------------------------------- textos
def emulator_text(emus: list[EmulatorInfo]) -> str:
    main = [e for e in emus if not e.auxiliary]
    aux = [e for e in emus if e.auxiliary]
    if not main:
        text = ("Nenhum emulador Android detectado. Abra o emulador (e o jogo) e clique em REANALISAR. "
                "Você pode continuar, mas a proteção do emulador só vale para o que está rodando.")
    else:
        text = "\n".join(
            f"Emulador detectado: {e.label}  ·  {e.process_count} processo(s) ({', '.join(e.exes[:5])})  ·  "
            f"{e.ram_mb:.0f} MB de RAM  ·  {e.cpu_percent:.1f}% de CPU" for e in main)
    if aux:
        text += "\nComponentes auxiliares detectados: " + ", ".join(e.label for e in aux) + "."
    return text


def game_text(snapshot: SystemSnapshot, cls: dict[int, Classification]) -> str:
    hints = sorted({p.name for p in snapshot.processes if any(k in _blob(p) for k in GAME_KEYS)})
    text = ""
    if hints:
        text = "Processos do jogo/Garena no Windows: " + ", ".join(hints) + ". "
    text += ("O Free Fire normalmente roda dentro do emulador (na máquina virtual), então este programa não consegue ver "
             "o jogo separado nem confirmar se ele está aberto. Ele protege o emulador inteiro, e isso mantém o jogo protegido.")
    return text


def protection_text(summary: list[tuple[str, int, float]], mixed: list[str]) -> str:
    if not summary:
        return "Protegido automaticamente: nada ainda (faça a análise)."
    total = sum(n for _, n, _ in summary)
    ram = sum(r for _, _, r in summary)
    parts = ", ".join(f"{label} {n}" for label, n, _ in summary)
    text = f"Protegido automaticamente: {total} processos (~{ram / 1024:.1f} GB de RAM). Por tipo: {parts}."
    if mixed:
        text += f" Mantidos inteiros por terem partes protegidas: {', '.join(mixed)}."
    return text


def candidates_text(c: list[AppGroup]) -> str:
    if not c:
        return "Nenhum aplicativo opcional está consumindo recursos relevantes agora."
    ram = sum(g.ram_mb for g in c)
    cpu = sum(g.cpu_percent for g in c)
    return (f"Candidatos a fechar: {len(c)} aplicativo(s), somando ~{ram / 1024:.1f} GB de RAM e {cpu:.1f}% de CPU. "
            "Você escolhe um por um; nada é fechado sem a sua confirmação.")


def session_text(sess: GamingSession, cpu_now: float, used_now_mb: float, avail_now_mb: float,
                 actions: list[ActionRecord]) -> str:
    closed_ram = sum(a.ram_mb for a in actions)
    d_avail = avail_now_mb - sess.before_avail_mb
    d_cpu = cpu_now - sess.before_cpu
    lines = [
        f"ANTES (ao ativar): CPU {sess.before_cpu:.0f}%  ·  RAM em uso {sess.before_used_mb / 1024:.1f} GB  ·  "
        f"disponível {sess.before_avail_mb / 1024:.1f} GB",
        f"AGORA (CPU = média dos últimos ~10 s): CPU {cpu_now:.0f}%  ·  RAM em uso {used_now_mb / 1024:.1f} GB  ·  "
        f"disponível {avail_now_mb / 1024:.1f} GB",
        f"Variação medida: RAM disponível {d_avail:+.0f} MB  ·  CPU {d_cpu:+.0f} pontos percentuais"
        + ("" if actions else "  (nenhum aplicativo foi encerrado por este programa: essa variação veio de outras causas)"),
        f"Encerrados nesta sessão: {len(actions)} aplicativo(s)  ·  ~{closed_ram:.0f} MB que estavam em uso por eles",
        "Atenção: a CPU oscila bastante e outros programas também mudam. Reduzir RAM ou CPU não garante aumento de FPS.",
    ]
    return "\n".join(lines)
