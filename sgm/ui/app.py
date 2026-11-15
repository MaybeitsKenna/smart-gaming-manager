"""Etapa 7: interface gráfica com encerramento individual e Gaming Mode (customtkinter, tema escuro).
ENCERRAR abre uma confirmação; primeiro tenta o fechamento normal e só oferece FORÇAR depois."""
from __future__ import annotations
import queue
import threading
import traceback
import time
import tkinter.messagebox as messagebox
from collections import deque

import customtkinter as ctk
import psutil

from ..classifier import Category
from ..gaming import (GamingSession, candidates, candidates_text, detect_emulators, emulator_text, game_text,
                      mixed_protected_names, protection_summary, protection_text, session_text)
from ..knowledge import AppGroup, format_card
from ..report import build_report
from .. import __version__
from ..service import AnalysisResult, analyze
from ..support import build_support_info, sanitize
from ..terminator import (ActionRecord, close_gracefully, confirmation_text, dependents, force_kill,
                          make_record, prepare)
from .report_window import ReportWindow
from .text_window import TextCopyWindow

CAT_COLOR = {
    Category.SEGURO: "#2ea043",
    Category.ATENCAO: "#bf8700",
    Category.PROTEGIDO: "#1f6feb",
    Category.DESCONHECIDO: "#8957e5",
}
FILTERS = {
    "Encerráveis": (Category.SEGURO, Category.ATENCAO),
    "Seguros": (Category.SEGURO,),
    "Atenção": (Category.ATENCAO,),
    "Protegidos": (Category.PROTEGIDO,),
    "Desconhecidos": (Category.DESCONHECIDO,),
    "Todos": tuple(Category),
}
CANDIDATES = "Maiores consumidores"
PAGE_SIZE = 40
MB_PER_GB = 1024


class App(ctk.CTk):
    def __init__(self) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        super().__init__()
        self.title(f"Smart Gaming Manager v{__version__}")
        self.geometry("1120x780")
        self.minsize(940, 620)

        self.result: AnalysisResult | None = None
        self.filter_name = "Encerráveis"
        self.shown = PAGE_SIZE
        self.busy = False
        self.events: queue.Queue = queue.Queue()
        self.actions: list[ActionRecord] = []
        self.gaming: GamingSession | None = None
        self.baseline: GamingSession | None = None      # medição "antes" usada no relatório
        self.gaming_pending = False
        self.gaming_panel_visible = False
        self.cpu_samples: deque = deque(maxlen=5)

        psutil.cpu_percent(None)          # "arma" a primeira leitura de CPU
        self._build_header()
        self._build_stats()
        self._build_toolbar()
        self._build_list()
        self._build_footer()
        self._tick()

    # ------------------------------------------------------------------ construção
    def _build_header(self) -> None:
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x", padx=18, pady=(14, 4))
        ctk.CTkLabel(head, text="Smart Gaming Manager", font=ctk.CTkFont(size=24, weight="bold")).pack(side="left")
        ctk.CTkLabel(head, text="entenda o que está rodando e escolha o que encerrar",
                     text_color="gray65").pack(side="left", padx=14, pady=(8, 0))

    def _stat_card(self, parent: ctk.CTkFrame, title: str) -> tuple[ctk.CTkLabel, ctk.CTkLabel]:
        card = ctk.CTkFrame(parent, corner_radius=12)
        card.pack(side="left", expand=True, fill="x", padx=6)
        ctk.CTkLabel(card, text=title, text_color="gray65").pack(anchor="w", padx=14, pady=(10, 0))
        value = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=24, weight="bold"))
        value.pack(anchor="w", padx=14)
        sub = ctk.CTkLabel(card, text="", text_color="gray65")
        sub.pack(anchor="w", padx=14, pady=(0, 10))
        return value, sub

    def _build_stats(self) -> None:
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=6)
        self.cpu_value, self.cpu_sub = self._stat_card(row, "CPU TOTAL")
        self.ram_value, self.ram_sub = self._stat_card(row, "RAM EM USO")
        self.proc_value, self.proc_sub = self._stat_card(row, "PROCESSOS ATIVOS")
        self.closable_value, self.closable_sub = self._stat_card(row, "APLICATIVOS ENCERRÁVEIS")

    def _build_toolbar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=18, pady=(6, 2))
        self.analyze_btn = ctk.CTkButton(bar, text="ANALISAR PC", width=160, height=38,
                                         font=ctk.CTkFont(weight="bold"), command=self._start_analysis)
        self.analyze_btn.pack(side="left")
        self.game_btn = ctk.CTkButton(bar, text="OTIMIZAR PARA JOGOS", width=210, height=38,
                                      font=ctk.CTkFont(weight="bold"), fg_color="#8957e5", hover_color="#6e40c9",
                                      command=self._game_mode)
        self.game_btn.pack(side="left", padx=10)
        self.report_btn = ctk.CTkButton(bar, text="GERAR RELATÓRIO", width=170, height=38, fg_color="gray30",
                                        hover_color="gray40", font=ctk.CTkFont(weight="bold"),
                                        command=self._make_report)
        self.report_btn.pack(side="left")
        self.status = ctk.CTkLabel(bar, text="Clique em ANALISAR PC para começar.", text_color="gray70")
        self.status.pack(side="left", padx=14)
        ctk.CTkButton(bar, text="INFO PARA SUPORTE", width=160, height=30, fg_color="gray25", hover_color="gray35",
                      command=self._support_info).pack(side="right")

        fbar = ctk.CTkFrame(self, fg_color="transparent")
        fbar.pack(fill="x", padx=18, pady=(10, 2))
        ctk.CTkLabel(fbar, text="Mostrar:", text_color="gray70").pack(side="left", padx=(0, 8))
        self.filter_btn = ctk.CTkSegmentedButton(fbar, values=list(FILTERS) + [CANDIDATES], command=self._on_filter)
        self.filter_btn.set(self.filter_name)
        self.filter_btn.pack(side="left")
        self.count_label = ctk.CTkLabel(fbar, text="", text_color="gray70")
        self.count_label.pack(side="right")

    def _build_gaming_panel(self) -> None:
        """Painel do Gaming Mode. Fica escondido até o botão OTIMIZAR PARA JOGOS ser usado."""
        panel = ctk.CTkFrame(self.body, corner_radius=12, border_width=2, border_color="#8957e5")
        self.gaming_panel = panel
        head = ctk.CTkFrame(panel, fg_color="transparent")
        head.pack(fill="x", padx=12, pady=(10, 2))
        ctk.CTkLabel(head, text="GAMING MODE", text_color="#b392f0",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
        ctk.CTkButton(head, text="SAIR DO GAMING MODE", width=190, height=28, fg_color="gray30", hover_color="gray40",
                      command=self._exit_gaming_mode).pack(side="right")
        ctk.CTkButton(head, text="REANALISAR", width=120, height=28,
                      command=self._start_analysis).pack(side="right", padx=8)

        def line(color: str = "gray85") -> ctk.CTkLabel:
            lab = ctk.CTkLabel(panel, text="", anchor="w", justify="left", wraplength=1040, text_color=color)
            lab.pack(fill="x", padx=14, pady=(2, 2))
            return lab

        self.g_emulator = line()
        self.g_game = line("gray65")
        self.g_protect = line()
        self.g_cands = line()
        self.g_summary = line("#9ecbff")
        ctk.CTkLabel(panel, text="", height=4).pack()

    def _build_list(self) -> None:
        # Um contêiner próprio com grid: linha 0 = painel do Gaming Mode (escondido), linha 1 = lista com rolagem.
        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.pack(fill="both", expand=True, padx=14, pady=8)
        self.body.grid_columnconfigure(0, weight=1)
        self.body.grid_rowconfigure(1, weight=1)
        self._build_gaming_panel()
        self.list = ctk.CTkScrollableFrame(self.body, corner_radius=12)
        self.list.grid(row=1, column=0, sticky="nsew")
        self._show_placeholder("Nenhuma análise ainda.")

    def _build_footer(self) -> None:
        ctk.CTkLabel(self, text="Reduzir uso de RAM ou CPU não garante aumento de FPS. Nenhum processo é encerrado "
                                "sem a sua confirmação.", text_color="gray60").pack(pady=(0, 10))

    # ------------------------------------------------------------------ estatísticas ao vivo
    def _tick(self) -> None:
        vm = psutil.virtual_memory()
        cpu_now = psutil.cpu_percent(None)
        self.cpu_samples.append(cpu_now)
        self.cpu_value.configure(text=f"{cpu_now:.0f}%")
        self.cpu_sub.configure(text=f"{psutil.cpu_count(logical=True)} núcleos lógicos")
        used = (vm.total - vm.available) / 1024 / 1024
        total = vm.total / 1024 / 1024
        self.ram_value.configure(text=f"{used / MB_PER_GB:.1f} GB")
        self.ram_sub.configure(text=f"disponível: {vm.available / 1024 / 1024 / MB_PER_GB:.1f} GB de {total / MB_PER_GB:.1f} GB")
        self.proc_value.configure(text=str(len(psutil.pids())))
        if self.gaming:
            self._refresh_session_summary()
        self.after(2000, self._tick)

    # ------------------------------------------------------------------ análise em segundo plano
    def _start_analysis(self) -> None:
        if self.busy:
            return
        self.busy = True
        self.analyze_btn.configure(state="disabled", text="ANALISANDO...")
        self.status.configure(text="Iniciando análise...")

        def work() -> None:
            try:
                res = analyze(lambda msg: self.events.put(("progress", msg)))
                self.events.put(("done", res))
            except Exception as exc:                       # mostra o erro na tela em vez de travar
                self.events.put(("error", f"{type(exc).__name__}: {exc}"))

        threading.Thread(target=work, daemon=True).start()
        self.after(150, self._poll)

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "progress":
                    self.status.configure(text=payload)
                elif kind == "done":
                    self._finish(payload)
                elif kind == "error":
                    self.busy = False
                    self.analyze_btn.configure(state="normal", text="ANALISAR PC")
                    self.status.configure(text="A análise falhou.")
                    messagebox.showerror("Erro na análise", payload)
        except queue.Empty:
            pass
        if self.busy:
            self.after(150, self._poll)

    def _finish(self, res: AnalysisResult) -> None:
        self.busy = False
        self.result = res
        self.shown = PAGE_SIZE
        self.analyze_btn.configure(state="normal", text="ANALISAR PC")
        self._update_closable_stats()
        if self.baseline is None:                      # primeira análise da sessão = ponto de partida do relatório
            snap = res.snapshot
            self.baseline = GamingSession(started=time.time(), before_cpu=snap.cpu_total_percent,
                                          before_used_mb=snap.ram_used_mb, before_avail_mb=snap.ram_available_mb,
                                          actions_start=len(self.actions))
        msg = "Análise concluída."
        if res.signature_error:
            msg += f"  Atenção: assinaturas não verificadas ({res.signature_error[:110]}). Tudo fica mais restrito."
        self.status.configure(text=msg)
        if self.gaming_pending:
            self.gaming_pending = False
            try:
                self._enter_gaming_mode()
            except Exception as exc:                       # mostra o erro na tela em vez de falhar em silêncio
                self.status.configure(text="O Gaming Mode falhou ao abrir.")
                messagebox.showerror("Erro no Gaming Mode", f"{type(exc).__name__}: {exc}")
        else:
            self._render()
            if self.gaming:
                self._refresh_gaming_panel()

    def _update_closable_stats(self) -> None:
        if not self.result:
            return
        closable = [g for g in self.result.groups if g.can_close]
        procs = sum(len(g.members) for g in closable)
        ram = sum(g.ram_mb for g in closable)
        self.closable_value.configure(text=str(len(closable)))
        self.closable_sub.configure(text=f"{procs} processos · {ram / MB_PER_GB:.1f} GB de RAM")

    # ------------------------------------------------------------------ trabalho em segundo plano genérico
    def run_bg(self, fn, on_done) -> None:
        q: queue.Queue = queue.Queue()

        def work() -> None:
            try:
                q.put(("ok", fn()))
            except Exception as exc:
                q.put(("err", f"{type(exc).__name__}: {exc}"))

        threading.Thread(target=work, daemon=True).start()

        def poll() -> None:
            try:
                kind, payload = q.get_nowait()
            except queue.Empty:
                self.after(150, poll)
                return
            on_done(kind, payload)

        self.after(150, poll)

    # ------------------------------------------------------------------ lista
    def _on_filter(self, name: str) -> None:
        self.filter_name = name
        self.shown = PAGE_SIZE
        self._render()

    def _clear_list(self) -> None:
        for w in self.list.winfo_children():
            w.destroy()

    def _show_placeholder(self, text: str) -> None:
        self._clear_list()
        ctk.CTkLabel(self.list, text=text, text_color="gray65").pack(pady=40)

    def _render(self) -> None:
        if not self.result:
            return
        if self.filter_name == CANDIDATES:
            groups = candidates(self.result.groups)
        else:
            wanted = FILTERS[self.filter_name]
            groups = [g for g in self.result.groups if g.category in wanted]
        self.count_label.configure(text=f"{min(self.shown, len(groups))} de {len(groups)} aplicativos")
        if not groups:
            self._show_placeholder("Nenhum aplicativo nesta categoria.")
            return
        self._clear_list()
        for g in groups[: self.shown]:
            self._row(g)
        if len(groups) > self.shown:
            ctk.CTkButton(self.list, text=f"Mostrar mais ({len(groups) - self.shown} restantes)", width=240,
                          command=self._more).pack(pady=12)

    def _more(self) -> None:
        self.shown += PAGE_SIZE
        self._render()

    def _row(self, g: AppGroup) -> None:
        e = g.explanation
        row = ctk.CTkFrame(self.list, corner_radius=10)
        row.pack(fill="x", padx=6, pady=5)
        row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(row, text=g.category.value, fg_color=CAT_COLOR[g.category], text_color="white",
                     corner_radius=6, width=112, height=24,
                     font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=12, pady=(10, 0), sticky="w")

        title = g.name
        if len(g.members) > 1:
            title += f"   ·   {len(g.members)} processos"
        if g.mixed:
            title += "   ·   grupo misto"
        ctk.CTkLabel(row, text=title, anchor="w",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=1, sticky="ew", padx=4, pady=(10, 0))

        usage = f"CPU {g.cpu_percent:.1f}%   ·   RAM {g.ram_mb:.0f} MB"
        if g.autostart:
            usage += "   ·   inicia com o Windows"
        ctk.CTkLabel(row, text=usage, anchor="e", text_color="gray70").grid(row=0, column=2, padx=12, pady=(10, 0))

        ctk.CTkLabel(row, text=e.what, anchor="w", justify="left", wraplength=720).grid(
            row=1, column=0, columnspan=2, sticky="ew", padx=12, pady=(4, 0))
        ctk.CTkLabel(row, text="Recomendação: " + e.recommendation, anchor="w", justify="left", wraplength=720,
                     text_color="gray70").grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=(2, 10))

        buttons = ctk.CTkFrame(row, fg_color="transparent")
        buttons.grid(row=1, column=2, rowspan=2, padx=12, pady=(4, 8))
        ctk.CTkButton(buttons, text="DETALHES", width=104, height=28, fg_color="gray30", hover_color="gray40",
                      command=lambda g=g: self._details(g)).pack(pady=(0, 6))
        if g.can_close:
            ctk.CTkButton(buttons, text="ENCERRAR", width=104, height=28, fg_color="#b62324", hover_color="#8e1519",
                          command=lambda g=g: self._confirm_close(g)).pack()
        else:
            ctk.CTkButton(buttons, text="BLOQUEADO", width=104, height=28, fg_color="gray25", state="disabled").pack()

    # ------------------------------------------------------------------ janelas
    def _text_window(self, title: str, text: str) -> None:
        win = ctk.CTkToplevel(self)
        win.title(title)
        win.geometry("820x560")
        box = ctk.CTkTextbox(win, wrap="word", font=ctk.CTkFont(family="Consolas", size=13))
        box.pack(fill="both", expand=True, padx=14, pady=(14, 8))
        box.insert("1.0", text)
        box.configure(state="disabled")
        ctk.CTkButton(win, text="FECHAR", width=120, command=win.destroy).pack(pady=(0, 14))
        win.after(120, win.lift)

    def _details(self, g: AppGroup) -> None:
        self._text_window(f"Detalhes: {g.name}", format_card(g))

    def _confirm_close(self, g: AppGroup) -> None:
        if self.busy or not self.result:
            return
        deps = dependents(g, self.result.snapshot)
        CloseDialog(self, g, deps)

    def register_action(self, g: AppGroup, rec: ActionRecord, removed: bool) -> None:
        self.actions.append(rec)
        if removed and self.result:
            self.result.groups = [x for x in self.result.groups if x is not g]
            self._update_closable_stats()
            self._render()
            if self.gaming:
                self._refresh_gaming_panel()
        total_ram = sum(a.ram_mb for a in self.actions)
        self.status.configure(text=f"Encerrados nesta sessão: {len(self.actions)} · ~{total_ram:.0f} MB em uso "
                                   "liberados. Clique em ANALISAR PC para atualizar os números.")

    # ------------------------------------------------------------------ Suporte e erros
    def _support_info(self) -> None:
        text = build_support_info(self.result, len(self.actions))
        TextCopyWindow(self, "Informações para suporte", text,
                       "Estas informações NÃO incluem nomes de programas, caminhos de arquivos nem o seu usuário. "
                       "Copie e envie junto com a descrição do problema.")

    def report_callback_exception(self, exc, val, tb) -> None:
        """Erros inesperados da interface viram uma janela com o texto para copiar (o .exe não tem terminal)."""
        self._errors_shown = getattr(self, "_errors_shown", 0) + 1
        if self._errors_shown > 3:
            return
        try:
            text = sanitize("".join(traceback.format_exception(exc, val, tb)))
            TextCopyWindow(self, "Erro inesperado", f"Smart Gaming Manager v{__version__}\n\n{text}",
                           "Algo deu errado. Copie o texto abaixo e envie para quem te passou o programa. "
                           "Seu nome de usuário foi removido do texto.")
        except Exception:
            pass

    # ------------------------------------------------------------------ Relatório
    def _make_report(self) -> None:
        if not self.result or not self.baseline:
            messagebox.showinfo("GERAR RELATÓRIO", "Faça uma análise primeiro (ANALISAR PC ou OTIMIZAR PARA JOGOS).")
            return
        if self.busy:
            return
        self.report_btn.configure(state="disabled", text="MEDINDO...")
        self.status.configure(text="Medindo a CPU por 5 segundos para o relatório...")

        def job():
            cpu = psutil.cpu_percent(interval=5)
            vm = psutil.virtual_memory()
            return cpu, vm.total / 1024 / 1024, vm.available / 1024 / 1024

        self.run_bg(job, self._show_report)

    def _show_report(self, kind: str, payload) -> None:
        self.report_btn.configure(state="normal", text="GERAR RELATÓRIO")
        if kind == "err":
            messagebox.showerror("Erro no relatório", payload)
            return
        cpu, total, avail = payload
        mine = self.actions[self.baseline.actions_start:]
        text = build_report(self.baseline, mine, self.result, cpu, total - avail, avail, total)
        self.status.configure(text="Relatório pronto.")
        ReportWindow(self, text)

    # ------------------------------------------------------------------ Gaming Mode
    def _game_mode(self) -> None:
        """Faz uma análise nova (para enxergar o emulador aberto) e depois ativa o painel."""
        if self.busy:
            return
        self.gaming_pending = True
        self._start_analysis()

    def _enter_gaming_mode(self) -> None:
        snap = self.result.snapshot
        self.gaming = GamingSession(started=time.time(), before_cpu=snap.cpu_total_percent,
                                    before_used_mb=snap.ram_used_mb, before_avail_mb=snap.ram_available_mb,
                                    actions_start=len(self.actions))
        self.baseline = self.gaming
        if not self.gaming_panel_visible:
            self.gaming_panel.grid(row=0, column=0, sticky="ew", pady=(0, 8))
            self.gaming_panel_visible = True
        self.filter_name = CANDIDATES
        self.filter_btn.set(CANDIDATES)
        self.shown = PAGE_SIZE
        self._refresh_gaming_panel()
        self._render()

    def _exit_gaming_mode(self) -> None:
        self.gaming = None
        if self.gaming_panel_visible:
            self.gaming_panel.grid_remove()
            self.gaming_panel_visible = False
        self.filter_name = "Encerráveis"
        self.filter_btn.set(self.filter_name)
        self.shown = PAGE_SIZE
        self._render()

    def _refresh_gaming_panel(self) -> None:
        if not (self.gaming and self.result):
            return
        snap, cls = self.result.snapshot, self.result.classifications
        self.g_emulator.configure(text=emulator_text(detect_emulators(snap, cls)))
        self.g_game.configure(text=game_text(snap, cls))
        self.g_protect.configure(text=protection_text(protection_summary(snap, cls),
                                                      mixed_protected_names(self.result.groups)))
        self.g_cands.configure(text=candidates_text(candidates(self.result.groups)))
        self._refresh_session_summary()

    def _refresh_session_summary(self) -> None:
        if not self.gaming:
            return
        vm = psutil.virtual_memory()
        avail = vm.available / 1024 / 1024
        used = vm.total / 1024 / 1024 - avail
        cpu = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0.0
        mine = self.actions[self.gaming.actions_start:]
        self.g_summary.configure(text=session_text(self.gaming, cpu, used, avail, mine))


class CloseDialog(ctk.CTkToplevel):
    """Confirmação de encerramento de UM aplicativo. Etapa 1: pedido normal. Etapa 2 (opcional): forçar."""

    def __init__(self, app: App, group: AppGroup, deps: list[str]) -> None:
        super().__init__(app)
        self.app = app
        self.group = group
        self.title(f"Encerrar {group.name}?")
        self.geometry("860x660")
        self.box = ctk.CTkTextbox(self, wrap="word", font=ctk.CTkFont(family="Consolas", size=13))
        self.box.pack(fill="both", expand=True, padx=14, pady=(14, 8))
        self.box.insert("1.0", confirmation_text(group, deps))
        self.box.configure(state="disabled")
        self.msg = ctk.CTkLabel(self, text="", wraplength=800, justify="left", anchor="w")
        self.msg.pack(fill="x", padx=18, pady=(0, 8))
        self.bar = ctk.CTkFrame(self, fg_color="transparent")
        self.bar.pack(pady=(0, 14))
        self._buttons_initial()
        self.after(120, self.lift)

    # ----- botões
    def _clear_bar(self) -> None:
        for w in self.bar.winfo_children():
            w.destroy()

    def _add(self, text: str, command, color: str | None = None) -> None:
        kwargs = {"fg_color": color} if color else {}
        ctk.CTkButton(self.bar, text=text, width=210, height=34, command=command, **kwargs).pack(side="left", padx=8)

    def _buttons_initial(self) -> None:
        self._clear_bar()
        self._add("CANCELAR", self.destroy, "gray30")
        self._add("ENCERRAR NORMALMENTE", lambda: self._start(False), "#b62324")

    def _buttons_close_only(self) -> None:
        self._clear_bar()
        self._add("FECHAR", self.destroy, "gray30")

    # ----- execução
    def _start(self, force: bool) -> None:
        self._clear_bar()
        self.msg.configure(text="Encerrando à força..." if force else
                           "Pedindo ao aplicativo para fechar (pode levar alguns segundos)...")
        group = self.group

        def job():
            plan = prepare(group)                      # revalida TUDO de novo, agora
            if plan.blocked:
                return ("blocked", plan, None)
            out = force_kill(plan) if force else close_gracefully(plan)
            return ("done", plan, out)

        self.app.run_bg(job, lambda kind, payload: self._done(kind, payload, force))

    def _done(self, kind: str, payload, force: bool) -> None:
        if kind == "err":
            self.msg.configure(text=f"Erro inesperado: {payload}\nNada de grave foi alterado.")
            self._buttons_close_only()
            return
        status, plan, out = payload
        if status == "blocked":
            self.msg.configure(text="NÃO ENCERRADO. " + plan.blocked)
            self._buttons_close_only()
            return

        remaining = len(out.still_running)
        if out.closed:
            rec = make_record(plan, out)
            self.app.register_action(self.group, rec, removed=(remaining == 0))
        if remaining == 0:
            freed = sum(t.info.ram_mb for t in plan.targets if t.proc.pid in set(out.closed))
            self.msg.configure(text=f"Encerrado: {len(out.closed)} processo(s), cerca de {freed:.0f} MB que estavam em "
                                    "uso. Para usar de novo, abra o aplicativo normalmente.")
            self._buttons_close_only()
        elif out.denied:
            self.msg.configure(text="Sem permissão para encerrar parte dos processos (eles têm privilégios elevados). "
                                    "Este programa não pede administrador automaticamente. Nada foi forçado além disso.")
            self._buttons_close_only()
        elif not force:
            why = ("O aplicativo não tem janela aberta (provavelmente está minimizado na bandeja ou em segundo plano)."
                   if out.windows_signaled == 0 else "O aplicativo recebeu o pedido, mas não fechou a tempo.")
            self.msg.configure(text=f"{why} {remaining} processo(s) continuam rodando.\n"
                                    "Você pode FORÇAR o encerramento, mas dados não salvos nele podem ser perdidos.")
            self._clear_bar()
            self._add("MANTER ABERTO", self.destroy, "gray30")
            self._add("FORÇAR ENCERRAMENTO", lambda: self._start(True), "#b62324")
        else:
            self.msg.configure(text=f"{remaining} processo(s) continuam rodando mesmo forçando. Nada mais será tentado.")
            self._buttons_close_only()
