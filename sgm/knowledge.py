"""Etapa 4: explicações em linguagem simples. SOMENTE informações verificáveis.

Fontes permitidas, em ordem:
  1) Texto curado, mas só para processos JÁ VERIFICADOS pelo classificador (assinatura + empresa, ou
     arquivo dentro da pasta do Windows). Nunca só pelo nome.
  2) Metadados do próprio executável (empresa, produto, descrição).
  3) Caso contrário: "Finalidade não identificada."
Nada aqui encerra processos ou altera o sistema."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .classifier import Category, Classification, SYSTEM_ROOT
from .models import ProcessInfo
from .signature import norm_path

# ---------- Aplicativos opcionais conhecidos: (o que faz, o que para de funcionar) ----------
APP_INFO = {
    "onedrive.exe": ("Aplicativo da Microsoft que sincroniza seus arquivos com a nuvem (OneDrive).",
                     "A sincronização para até você abrir o OneDrive de novo. Arquivos novos não sobem para a nuvem nesse período."),
    "discord.exe": ("Aplicativo de conversa por voz e texto Discord.",
                    "Você sai de chamadas de voz e deixa de receber mensagens até abrir o Discord de novo."),
    "steam.exe": ("Cliente da loja e da biblioteca de jogos Steam.",
                  "Downloads e atualizações em andamento na Steam são interrompidos."),
    "steamwebhelper.exe": ("Componente que desenha a interface do cliente Steam (loja, biblioteca e chat).",
                           "A janela da Steam pode ficar em branco ou fechar."),
    "spotify.exe": ("Aplicativo de música Spotify.", "A música para de tocar."),
    "spotifylauncher.exe": ("Inicializador do Spotify.", "Nada visível além do Spotify não iniciar sozinho."),
    "chrome.exe": ("Navegador Google Chrome.", "Todas as abas e janelas do Chrome fecham. Dados de formulários não enviados podem ser perdidos."),
    "msedge.exe": ("Navegador Microsoft Edge.", "Todas as abas e janelas do Edge fecham. Dados de formulários não enviados podem ser perdidos."),
    "firefox.exe": ("Navegador Mozilla Firefox.", "Todas as abas e janelas do Firefox fecham."),
    "opera.exe": ("Navegador Opera.", "Todas as abas e janelas do Opera fecham."),
    "brave.exe": ("Navegador Brave.", "Todas as abas e janelas do Brave fecham."),
    "telegram.exe": ("Aplicativo de mensagens Telegram.", "Você deixa de receber mensagens do Telegram neste computador."),
    "whatsapp.exe": ("Aplicativo de mensagens WhatsApp.", "Você deixa de receber mensagens do WhatsApp neste computador."),
    "dropbox.exe": ("Aplicativo de sincronização de arquivos Dropbox.", "A sincronização para até você abrir o Dropbox de novo."),
    "googledrivefs.exe": ("Aplicativo de sincronização do Google Drive.", "A sincronização para até você abrir o Google Drive de novo."),
    "epicgameslauncher.exe": ("Loja e iniciador de jogos da Epic Games.", "Downloads e atualizações em andamento são interrompidos."),
    "epicwebhelper.exe": ("Componente de interface do Epic Games Launcher.", "A janela do Epic Games Launcher pode fechar."),
    "ms-teams.exe": ("Microsoft Teams (chamadas e reuniões).", "Você sai de reuniões e deixa de receber mensagens do Teams."),
    "teams.exe": ("Microsoft Teams (chamadas e reuniões).", "Você sai de reuniões e deixa de receber mensagens do Teams."),
    "skype.exe": ("Aplicativo de chamadas Skype.", "Você sai de chamadas e deixa de receber mensagens."),
    "slack.exe": ("Aplicativo de mensagens de trabalho Slack.", "Você deixa de receber mensagens do Slack neste computador."),
    "zoom.exe": ("Aplicativo de videochamadas Zoom.", "Você sai de reuniões em andamento."),
    "claude.exe": ("Aplicativo de desktop do Claude, assistente de IA da Anthropic.", "O aplicativo fecha. Abra-o de novo normalmente."),
    "eadesktop.exe": ("Aplicativo de jogos da Electronic Arts (EA app).", "Downloads e atualizações em andamento são interrompidos."),
    "upc.exe": ("Ubisoft Connect, loja e iniciador de jogos da Ubisoft.", "Downloads e atualizações em andamento são interrompidos."),
    "battle.net.exe": ("Iniciador de jogos da Blizzard (Battle.net).", "Downloads e atualizações em andamento são interrompidos."),
    "code.exe": ("Editor de código Visual Studio Code.",
                 "Arquivos com alterações não salvas podem ser perdidos, e terminais e extensões abertos fecham."),
    "msedgewebview2.exe": ("Componente da Microsoft que permite a programas exibir conteúdo web dentro deles (WebView2).",
                           "Programas que usam esse componente (como alguns painéis do Windows e apps) podem travar ou ficar em branco."),
}

# ---------- Componentes do Windows (só usados com o arquivo na pasta do Windows) ----------
SYSTEM_INFO = {
    "explorer.exe": "Mostra a área de trabalho, a barra de tarefas e o Explorador de Arquivos.",
    "svchost.exe": "Hospeda vários serviços do Windows (rede, áudio, atualizações etc.).",
    "csrss.exe": "Processo essencial do Windows que gerencia janelas e o console.",
    "wininit.exe": "Inicializa serviços essenciais do Windows na partida.",
    "winlogon.exe": "Gerencia o login e o logoff do Windows.",
    "lsass.exe": "Verifica logins e aplica as políticas de segurança do Windows.",
    "services.exe": "Gerenciador de serviços do Windows (inicia e controla os serviços).",
    "audiodg.exe": "Processa o áudio do Windows (mixagem e efeitos).",
    "dwm.exe": "Gerenciador de janelas: desenha janelas, transparências e efeitos da área de trabalho.",
    "smss.exe": "Primeiro processo de usuário do Windows; inicia a sessão.",
    "sihost.exe": "Gerencia partes da interface do Windows, como o menu Iniciar e as notificações.",
    "ctfmon.exe": "Gerencia entrada de texto e o idioma do teclado.",
    "conhost.exe": "Hospeda janelas de console (prompt de comando e terminais).",
    "dllhost.exe": "Hospeda componentes do Windows usados por outros programas.",
    "spoolsv.exe": "Gerencia a fila de impressão.",
    "wudfhost.exe": "Hospeda drivers de dispositivos que rodam em modo usuário.",
    "fontdrvhost.exe": "Processa fontes de forma isolada e segura.",
    "runtimebroker.exe": "Controla as permissões de aplicativos da Microsoft Store.",
    "taskhostw.exe": "Hospeda tarefas em segundo plano do Windows.",
    "searchhost.exe": "Parte da pesquisa do Windows (barra de pesquisa).",
    "startmenuexperiencehost.exe": "Exibe o menu Iniciar.",
    "textinputhost.exe": "Teclado virtual, emojis e entrada de texto do Windows.",
    "applicationframehost.exe": "Exibe as janelas de aplicativos da Microsoft Store.",
    "wmiprvse.exe": "Fornece informações do sistema a outros programas (WMI).",
    "searchindexer.exe": "Indexa arquivos para a pesquisa do Windows ficar rápida.",
    "powershell.exe": "Terminal PowerShell do Windows.",
    "lockapp.exe": "Tela de bloqueio do Windows.",
    "smartscreen.exe": "Filtro SmartScreen do Windows, que avisa sobre programas e sites perigosos.",
}
# Sem arquivo .exe legível: só pelo nome exato do núcleo do Windows
KERNEL_INFO = {
    "system": "Núcleo do Windows (drivers e funções internas do sistema).",
    "registry": "Mantém o Registro do Windows na memória.",
    "memcompression": "Compacta dados da memória RAM para economizar espaço.",
    "system idle process": "Mostra a CPU que está livre. Não é um programa real.",
}
DEFENDER_INFO = {
    "msmpeng.exe": "Mecanismo antivírus do Microsoft Defender.",
    "nissrv.exe": "Proteção de rede do Microsoft Defender.",
    "mpdefendercoreservice.exe": "Serviço central do Microsoft Defender.",
}
TAG_INFO = {
    "emulator": "Parte do emulador Android ou do jogo. É nele que o Free Fire roda.",
    "audio": "Relacionado ao áudio do computador.",
    "network": "Relacionado à rede ou à conectividade (Wi-Fi, VPN, Bluetooth etc.).",
    "driver": "Software de driver, hardware ou periférico.",
    "security": "Software de segurança (antivírus/Defender).",
    "input": "Relacionado a teclado, mouse ou controle.",
    "self": "Faz parte deste gerenciador ou do terminal onde ele está rodando.",
}
INSTALLER_WORDS = ("setup", "install", "update", "updater")

_RANK = {Category.PROTEGIDO: 4, Category.DESCONHECIDO: 3, Category.ATENCAO: 2, Category.SEGURO: 1}


@dataclass
class Explanation:
    what: str
    consumption: str
    game_impact: str
    side_effects: str
    recommendation: str
    basis: list[str] = field(default_factory=list)


@dataclass
class AppGroup:
    key: str
    name: str
    members: list[ProcessInfo]
    category: Category            # a mais restritiva entre os membros
    mixed: bool
    ram_mb: float
    cpu_percent: float
    autostart: bool
    can_close: bool
    explanation: Explanation
    tags: set[str] = field(default_factory=set)      # união das marcas de proteção dos processos do grupo

    @property
    def pids(self) -> list[int]:
        return [m.pid for m in self.members]


def _under_windows(path: Optional[str]) -> bool:
    return bool(path) and norm_path(path).startswith(SYSTEM_ROOT.rstrip("\\") + "\\")


def _no_real_path(path: Optional[str]) -> bool:
    """Processos do núcleo (System, Registry, MemCompression) não têm arquivo .exe de verdade:
    o caminho vem vazio ou só com o nome, sem pasta."""
    return not path or ("\\" not in path and "/" not in path)


def _what_it_does(rep: ProcessInfo, c: Classification) -> tuple[str, str]:
    """Retorna (o que faz, efeitos de encerrar). Usa só fontes verificáveis."""
    name = rep.name.lower()
    meta = rep.meta
    vendor = meta.company or c.signer
    from_meta = None
    if meta.description or meta.product:
        from_meta = f"{meta.description or meta.product}" + (f", da empresa {vendor}" if vendor else "")
        from_meta = from_meta.rstrip(".") + "."

    if name in APP_INFO and c.category in (Category.SEGURO, Category.ATENCAO):
        return APP_INFO[name]

    if name in KERNEL_INFO and _no_real_path(rep.exe_path):
        return KERNEL_INFO[name], ""
    if name in SYSTEM_INFO and _under_windows(rep.exe_path):
        return SYSTEM_INFO[name], ""
    if name in DEFENDER_INFO and rep.exe_path and "windows defender" in rep.exe_path.lower():
        return DEFENDER_INFO[name], ""

    for tag in ("emulator", "self", "audio", "network", "input", "security", "driver"):
        if tag in c.tags:
            extra = f" Detalhe do arquivo: {from_meta}" if from_meta else ""
            return TAG_INFO[tag] + extra, ""

    if "windows" in c.tags and from_meta:
        return f"Arquivo na pasta do Windows. {from_meta}", ""
    if from_meta and c.category != Category.DESCONHECIDO:
        return from_meta, ""
    if from_meta:
        return f"Finalidade não identificada. O arquivo informa apenas: {from_meta}", ""
    return "Finalidade não identificada.", ""


def _impact(ram: float, cpu: float) -> str:
    level = "BAIXO"
    if ram >= 150 or cpu >= 1:
        level = "MÉDIO"
    if ram >= 500 or cpu >= 5:
        level = "ALTO"
    return level


def build_groups(processes: list[ProcessInfo], cls: dict[int, Classification]) -> list[AppGroup]:
    buckets: dict[str, list[ProcessInfo]] = {}
    for p in processes:
        key = norm_path(p.exe_path) if p.exe_path else f"sem-caminho:{p.name.lower()}"
        buckets.setdefault(key, []).append(p)

    groups: list[AppGroup] = []
    for key, members in buckets.items():
        cats = {cls[m.pid].category for m in members}
        eff = max(cats, key=lambda c: _RANK[c])
        rep = next(m for m in members if cls[m.pid].category == eff)
        c = cls[rep.pid]
        ram = round(sum(m.ram_mb for m in members), 1)
        cpu = round(sum(m.cpu_percent for m in members), 1)
        autostart = any(cls[m.pid].autostart for m in members)
        mixed = len(cats) > 1
        can_close = eff in (Category.SEGURO, Category.ATENCAO)

        what, effects = _what_it_does(rep, c)
        n = len(members)
        consumption = (f"{cpu:.1f}% de CPU e {ram:.0f} MB de RAM"
                       + (f" (somando {n} processos)" if n > 1 else ""))

        installer = any(w in rep.name.lower() for w in INSTALLER_WORDS)
        if installer and can_close:
            effects = ("Pode ser uma instalação ou atualização em andamento. Encerrar pode deixar o programa "
                       "incompleto ou corrompido.")

        if eff == Category.PROTEGIDO:
            impact = "Não aplicável: processo protegido."
            if mixed:
                recommendation = ("NÃO ENCERRAR. Este aplicativo tem processos protegidos misturados com outros "
                                  f"({', '.join(sorted(x.value for x in cats if x != Category.PROTEGIDO))}), "
                                  "então nada dele será encerrado por este programa.")
            else:
                recommendation = "NÃO ENCERRAR."
        elif eff == Category.DESCONHECIDO:
            impact = "Não avaliado: finalidade não identificada."
            recommendation = ("Finalidade não identificada. Este programa NÃO encerra processos desconhecidos. "
                              "Pesquise o nome do arquivo antes de qualquer decisão.")
            if "suspect" in c.tags:
                recommendation = "ALERTA: " + c.reason + " Não encerrar por aqui; verifique com seu antivírus."
        else:
            level = _impact(ram, cpu)
            impact = (f"Impacto estimado: {level}. Usa {ram:.0f} MB de RAM e {cpu:.1f}% de CPU neste momento. "
                      "Fechar libera esses recursos, mas isso não garante mais FPS.")
            if installer:
                recommendation = "Aguarde terminar. Não recomendado encerrar agora."
            elif eff == Category.SEGURO:
                recommendation = ("Pode ser encerrado temporariamente. Para voltar a usar, é só abrir o aplicativo "
                                  "de novo normalmente.")
            else:
                recommendation = ("Só encerre se tiver certeza de que não está usando. Pode interromper alguma "
                                  "função. Para voltar a usar, abra o aplicativo de novo normalmente.")
            if autostart:
                impact += " Ele inicia junto com o Windows."

        basis = list(c.evidence)
        if rep.meta.company:
            basis.insert(0, f"Empresa informada pelo arquivo: {rep.meta.company}")
        if mixed:
            basis.append("Categorias dos processos do grupo: " + ", ".join(
                f"{cat.value} ({sum(1 for m in members if cls[m.pid].category == cat)})" for cat in cats))

        tags: set[str] = set()
        for m in members:
            tags |= cls[m.pid].tags
        groups.append(AppGroup(key, rep.name, members, eff, mixed, ram, cpu, autostart, can_close,
                               Explanation(what, consumption, impact, effects, recommendation, basis), tags))
    groups.sort(key=lambda g: g.ram_mb, reverse=True)
    return groups


def format_card(g: AppGroup) -> str:
    e = g.explanation
    lines = [
        f"Processo        : {g.name}" + (f"  ({len(g.members)} processos)" if len(g.members) > 1 else ""),
        f"Categoria       : {g.category.value}" + ("  (grupo misto)" if g.mixed else ""),
        f"O que faz       : {e.what}",
        f"Consumo         : {e.consumption}",
        f"Impacto no jogo : {e.game_impact}",
    ]
    if e.side_effects:
        lines.append(f"Se encerrar     : {e.side_effects}")
    lines.append(f"Recomendação    : {e.recommendation}")
    if e.basis:
        lines.append("Base da análise :")
        lines += [f"   - {b}" for b in e.basis]
    return "\n".join(lines)