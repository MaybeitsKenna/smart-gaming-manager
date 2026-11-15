"""Etapa 3: classificação de segurança. Princípio: NA DÚVIDA, PROTEGE.

Nenhuma decisão depende só do nome. As evidências usadas são: caminho, dono do processo,
assinatura digital, empresa/descrição do executável e relação com outros processos."""
from __future__ import annotations
import ntpath
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .models import ProcessInfo
from .signature import SigInfo, norm_path, signer_name


class Category(str, Enum):
    SEGURO = "SEGURO"
    ATENCAO = "ATENÇÃO"
    PROTEGIDO = "PROTEGIDO"
    DESCONHECIDO = "DESCONHECIDO"


@dataclass
class Classification:
    category: Category
    reason: str
    evidence: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)      # ex.: windows, emulator, audio, network, driver, security, suspect
    sig_status: str = "Unavailable"
    signer: Optional[str] = None
    autostart: bool = False


SYSTEM_ROOT = norm_path(os.environ.get("SystemRoot", r"C:\Windows"))

# Nomes de processos essenciais do Windows. Se um processo usa um destes nomes FORA da pasta do
# Windows, ele é marcado como suspeito (possível imitação).
CORE_WINDOWS_NAMES = {
    "system", "registry", "memcompression", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "audiodg.exe", "dwm.exe", "explorer.exe",
    "fontdrvhost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "runtimebroker.exe", "conhost.exe",
    "dllhost.exe", "spoolsv.exe", "wudfhost.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "textinputhost.exe", "securityhealthservice.exe", "securityhealthsystray.exe",
    "searchindexer.exe", "taskmgr.exe", "wmiprvse.exe", "dashost.exe", "lsm.exe",
}

# Termos (no caminho/empresa/produto/descrição) que indicam emulador Android ou o jogo.
# Aqui o nome PODE ser usado porque o erro é seguro: o pior caso é proteger algo a mais.
EMULATOR_GAME_KEYS = (
    "bluestacks", "bstk", "hd-player", "hd-adb", "ldplayer", "ldmultiplayer", "dnplayer", "ldvbox",
    "memu", "microvirt", "bignox", "noxplayer", "gameloop", "tencent gaming", "aow_exe", "tgp_daemon",
    "txgameassistant", "androidemulator",
    "msi app player", "msiappplayer", "genymotion", "qemu-system", "wsaclient", "subsystem for android",
    "android debug bridge", "adb.exe", "virtualbox", "vboxheadless", "vboxsvc", "smartgaga", "koplayer",
    "free fire", "freefire", "garena",
)
EMULATOR_EXACT_NAMES = {"nox.exe", "noxvmhandle.exe", "nox_adb.exe", "adb.exe"}

AUDIO_NET_WORDS = {
    "audio": ("audio", "áudio", "sound", "realtek hd", "waves"),
    "network": ("wi-fi", "wifi", "wlan", "ethernet", "bluetooth", "network adapter", "vpn", "firewall"),
}
HARDWARE_VENDORS = (r"nvidia", r"intel", r"realtek", r"advanced micro devices", r"logitech",
                    r"razer", r"corsair", r"steelseries")
SECURITY_VENDORS = (r"kaspersky", r"avast", r"\bavg\b", r"bitdefender", r"\beset\b", r"norton", r"mcafee",
                    r"malwarebytes", r"avira", r"sophos", r"trend micro", r"windows defender")

# Aplicativos opcionais conhecidos: nome do processo -> trecho esperado da empresa/assinante.
# Só é SEGURO se a assinatura for válida E a empresa bater (nome sozinho não basta).
KNOWN_OPTIONAL = {
    "onedrive.exe": "microsoft", "discord.exe": "discord", "steam.exe": "valve", "steamwebhelper.exe": "valve",
    "spotify.exe": "spotify", "spotifylauncher.exe": "spotify", "chrome.exe": "google", "msedge.exe": "microsoft",
    "firefox.exe": "mozilla", "opera.exe": "opera", "brave.exe": "brave", "telegram.exe": "telegram",
    "whatsapp.exe": "whatsapp", "dropbox.exe": "dropbox", "googledrivefs.exe": "google",
    "epicgameslauncher.exe": "epic", "epicwebhelper.exe": "epic", "ms-teams.exe": "microsoft",
    "teams.exe": "microsoft", "skype.exe": "skype", "slack.exe": "slack", "zoom.exe": "zoom",
    "claude.exe": "anthropic", "eadesktop.exe": "electronic arts", "upc.exe": "ubisoft",
    "battle.net.exe": "blizzard",
}
INPUT_HINTS = ("gameinput", "rawinput")          # teclado, mouse e controles
TERMINAL_HOSTS = {"openconsole.exe"}             # hospedam terminais (ex.: o do VS Code)
WINDOWSAPPS_ROOT = norm_path(os.environ.get("ProgramFiles", r"C:\Program Files") + r"\WindowsApps")

# Identificados, mas fechar pode causar perda de trabalho ou afetar outros apps.
KNOWN_ATTENTION = {"code.exe": "microsoft", "msedgewebview2.exe": "microsoft"}


@dataclass
class Context:
    me: str
    own_pids: set[int]
    startup: set[str]


def _under(path: str, root: str) -> bool:
    return norm_path(path).startswith(root.rstrip("\\") + "\\")


def _matches_any(text: str, patterns) -> bool:
    return any(re.search(p, text) for p in patterns)


def _emulator_hit(p: ProcessInfo) -> bool:
    name = p.name.lower()
    if name in EMULATOR_EXACT_NAMES:
        return True
    blob = " ".join(filter(None, [p.exe_path, p.name, p.meta.company, p.meta.product, p.meta.description])).lower()
    return any(k in blob for k in EMULATOR_GAME_KEYS)


def _audio_net_hit(p: ProcessInfo) -> Optional[str]:
    blob = " ".join(filter(None, [p.name, p.meta.product, p.meta.description])).lower()
    for tag, words in AUDIO_NET_WORDS.items():
        if any(w in blob for w in words):
            return tag
    return None


def _classify_one(p: ProcessInfo, sig: Optional[SigInfo], ctx: Context) -> Classification:
    name = p.name.lower()
    path = p.exe_path
    status = sig.status if sig else "Unavailable"
    signer = signer_name(sig.subject) if sig else None
    sig_ok = status == "Valid"
    unverifiable = status in ("Unavailable", "Error", "UnknownError")   # a verificação em si falhou
    vendor_text = f"{p.meta.company or ''} {signer or ''}".lower()
    autostart = bool(path and norm_path(path) in ctx.startup)

    def mk(cat, reason, tags=(), evidence=()):
        return Classification(cat, reason, list(evidence), set(tags), status, signer, autostart)

    sig_line = f"Assinatura digital válida: {signer}" if sig_ok else f"Assinatura digital: {status}"

    # 1) O próprio programa e o terminal que o executa
    if p.pid in ctx.own_pids:
        return mk(Category.PROTEGIDO, "Faz parte do programa/terminal que está executando o Smart Gaming Manager.",
                  {"self"})

    # 2) Sem caminho legível -> não dá para verificar nada
    if not path or p.access_denied:
        return mk(Category.PROTEGIDO, "Não foi possível ler o caminho do executável (acesso negado ou processo do núcleo "
                  "do sistema). Na dúvida, protegido.", {"system"})

    # 3) Dono diferente do usuário atual (SYSTEM, serviços, outros usuários)
    if not p.username:
        return mk(Category.PROTEGIDO, "Processo de sistema ou serviço (o dono não é legível sem privilégios de "
                  "administrador). Na dúvida, protegido.", {"system"}, [f"Caminho: {path}"])
    if p.username.lower() != ctx.me:
        return mk(Category.PROTEGIDO, f"Pertence ao sistema ou a outra conta ({p.username}).",
                  {"system"}, [f"Caminho: {path}"])

    in_windows = _under(path, SYSTEM_ROOT)

    # 4) Nome de processo do Windows, mas arquivo fora da pasta do Windows -> suspeito
    if name in CORE_WINDOWS_NAMES and not in_windows:
        return mk(Category.DESCONHECIDO,
                  "ALERTA: usa o nome de um processo do Windows, mas o arquivo NÃO está na pasta do sistema.",
                  {"suspect"}, [f"Caminho: {path}", sig_line])

    # 5) Dentro da pasta do Windows
    if in_windows:
        ev = [f"Caminho dentro de {SYSTEM_ROOT}", sig_line]
        if not sig_ok and not unverifiable:
            ev.append("Atenção: assinatura não confere, mas o caminho é protegido. Mantido PROTEGIDO.")
        if sig_ok and signer and "microsoft" not in signer.lower():
            return mk(Category.PROTEGIDO, f"Arquivo na pasta do Windows, assinado por {signer} "
                      "(provavelmente driver ou utilitário instalado). Protegido.", {"windows", "driver"}, ev)
        company = p.meta.company or ""
        if company and "microsoft" not in company.lower():
            product = p.meta.product or p.meta.description or "utilitário/driver"
            return mk(Category.PROTEGIDO, f"Arquivo na pasta do Windows, de {company} ({product}). Protegido.",
                      {"windows", "driver"}, ev)
        return mk(Category.PROTEGIDO, "Componente do Windows.", {"windows"}, ev)

    # 5b) Hospedeiros de terminal: encerrar derrubaria terminais abertos, inclusive o que roda este programa
    if name in TERMINAL_HOSTS:
        return mk(Category.PROTEGIDO, "Componente que hospeda terminais (console). Encerrar fecharia terminais "
                  "abertos, inclusive o que pode estar executando este programa.", {"system"},
                  [sig_line, f"Caminho: {path}"])

    # 6) Emulador Android / jogo
    if _emulator_hit(p):
        return mk(Category.PROTEGIDO, "Relacionado a emulador Android ou ao jogo (protegido automaticamente).",
                  {"emulator"}, [f"Caminho: {path}", sig_line])

    # 7) Áudio / rede
    tag = _audio_net_hit(p)
    if tag:
        label = "áudio" if tag == "audio" else "rede/conectividade"
        return mk(Category.PROTEGIDO, f"Parece relacionado a {label}. Protegido por precaução.", {tag},
                  [f"Descrição: {p.meta.description or '-'}"])

    # 7b) Dispositivos de entrada (teclado, mouse, controle)
    if any(h in name for h in INPUT_HINTS):
        return mk(Category.PROTEGIDO, "Relacionado a dispositivos de entrada (teclado, mouse, controle). "
                  "Protegido por precaução.", {"input"}, [sig_line, f"Caminho: {path}"])

    # 7c) Microsoft Defender / Segurança do Windows fora da pasta do Windows
    sec_blob = f"{path} {p.name} {p.meta.description or ''}".lower()
    if "defender" in sec_blob or "securityhealth" in sec_blob:
        return mk(Category.PROTEGIDO, "Componente de segurança do Windows (Microsoft Defender). "
                  "Nunca encerrado por este programa.", {"security"}, [sig_line, f"Caminho: {path}"])

    # 8) Drivers/periféricos e segurança (exigem assinatura válida)
    if sig_ok and _matches_any(vendor_text, HARDWARE_VENDORS):
        return mk(Category.PROTEGIDO, "Software de driver/hardware/periférico de fabricante verificado.",
                  {"driver"}, [sig_line, f"Empresa: {p.meta.company or signer}"])
    if sig_ok and _matches_any(vendor_text, SECURITY_VENDORS):
        return mk(Category.PROTEGIDO, "Software de segurança/antivírus. Nunca encerrado por este programa.",
                  {"security"}, [sig_line])

    # 9) Aplicativos opcionais conhecidos (nome + empresa + assinatura)
    if name in KNOWN_OPTIONAL:
        if sig_ok and KNOWN_OPTIONAL[name] in vendor_text:
            return mk(Category.SEGURO, "Aplicativo opcional conhecido e verificado.", {"optional"},
                      [sig_line, f"Empresa: {p.meta.company or signer}", f"Caminho: {path}"])
        if unverifiable:
            return mk(Category.DESCONHECIDO,
                      "Nome de aplicativo conhecido, mas a assinatura não pôde ser verificada. Mantido sem ação.",
                      set(), [f"Caminho: {path}"])
        return mk(Category.DESCONHECIDO,
                  "Usa o nome de um aplicativo conhecido, mas a assinatura/empresa não confere.",
                  {"suspect"}, [sig_line, f"Caminho: {path}"])

    # 10) Conhecidos que exigem atenção
    if name in KNOWN_ATTENTION and sig_ok and KNOWN_ATTENTION[name] in vendor_text:
        return mk(Category.ATENCAO, "Identificado e verificado, mas encerrar pode interromper outros programas "
                  "ou causar perda de trabalho não salvo.", {"attention"}, [sig_line])

    # 11) Genérico
    if sig_ok and (p.meta.description or p.meta.product):
        return mk(Category.ATENCAO, f"Programa assinado por {signer or p.meta.company or 'empresa não identificada'}, "
                  "fora da lista de aplicativos conhecidos. Encerrar pode interromper alguma função.", {"third_party"},
                  [sig_line, f"Descrição: {p.meta.description or p.meta.product}", f"Caminho: {path}"])
    if sig_ok:
        return mk(Category.DESCONHECIDO, f"Assinado por {signer or 'empresa não identificada'}, mas sem descrição no "
                  "arquivo. Finalidade não identificada.",
                  set(), [sig_line, f"Caminho: {path}"])
    if (status == "NotSigned" and _under(path, WINDOWSAPPS_ROOT)
            and (p.meta.description or p.meta.product or p.meta.company)):
        return mk(Category.ATENCAO, "App empacotado (Microsoft Store). O arquivo não tem assinatura própria: a "
                  "assinatura fica no pacote, instalado em pasta protegida do Windows.", {"third_party", "packaged"},
                  [f"Caminho: {path}", f"Empresa: {p.meta.company or '-'}"])
    if status == "NotSigned":
        return mk(Category.DESCONHECIDO, "Sem assinatura digital. Finalidade não identificada.", set(),
                  [f"Caminho: {path}"])
    if unverifiable:
        return mk(Category.DESCONHECIDO, "Assinatura não pôde ser verificada. Finalidade não identificada.", set(),
                  [f"Caminho: {path}"])
    return mk(Category.DESCONHECIDO, f"Assinatura inválida ({status}). Tratado como suspeito.", {"suspect"},
              [f"Caminho: {path}"])


def classify_all(processes: list[ProcessInfo], sigs: dict[str, SigInfo], startup: set[str],
                 me: Optional[str] = None) -> dict[int, Classification]:
    if me is None:
        import psutil
        try:
            me = psutil.Process().username()
        except Exception:
            me = ""
    by_pid = {p.pid: p for p in processes}

    # PID atual + ancestrais (terminal, VS Code que hospeda o terminal etc.)
    own: set[int] = set()
    cur = os.getpid()
    for _ in range(8):
        own.add(cur)
        parent = by_pid.get(cur).parent_pid if cur in by_pid else None
        if not parent or parent in own:
            break
        cur = parent

    ctx = Context(me=(me or "").lower(), own_pids=own, startup=startup)
    result: dict[int, Classification] = {}
    for p in processes:
        sig = sigs.get(norm_path(p.exe_path)) if p.exe_path else None
        result[p.pid] = _classify_one(p, sig, ctx)

    # Filhos de processos de emulador/jogo também são protegidos (propaga até estabilizar)
    changed = True
    while changed:
        changed = False
        for p in processes:
            c = result[p.pid]
            parent = result.get(p.parent_pid) if p.parent_pid is not None else None
            if (parent and "emulator" in parent.tags and c.category != Category.PROTEGIDO
                    and "suspect" not in c.tags):
                result[p.pid] = Classification(
                    Category.PROTEGIDO, f"Processo filho de {p.parent_name} (emulador/jogo). Protegido.",
                    c.evidence, {"emulator"}, c.sig_status, c.signer, c.autostart)
                changed = True
    return result