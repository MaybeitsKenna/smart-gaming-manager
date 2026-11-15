"""Janela do relatório. Só grava em arquivo se o usuário clicar em SALVAR EM ARQUIVO."""
from __future__ import annotations
import time
import tkinter.filedialog as filedialog

import customtkinter as ctk


class ReportWindow(ctk.CTkToplevel):
    """Mostra o relatório e permite copiar ou salvar."""

    def __init__(self, app, text: str) -> None:
        super().__init__(app)
        self.text = text
        self.title("Relatório - Smart Gaming Manager")
        self.geometry("900x700")
        box = ctk.CTkTextbox(self, wrap="word", font=ctk.CTkFont(family="Consolas", size=13))
        box.pack(fill="both", expand=True, padx=14, pady=(14, 8))
        box.insert("1.0", text)
        box.configure(state="disabled")
        self.msg = ctk.CTkLabel(self, text="Nada é salvo em arquivo, a menos que você clique em SALVAR EM ARQUIVO.",
                                text_color="gray70")
        self.msg.pack(pady=(0, 6))
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(pady=(0, 14))
        ctk.CTkButton(bar, text="COPIAR", width=150, command=self._copy).pack(side="left", padx=8)
        ctk.CTkButton(bar, text="SALVAR EM ARQUIVO", width=190, command=self._save).pack(side="left", padx=8)
        ctk.CTkButton(bar, text="FECHAR", width=150, fg_color="gray30", command=self.destroy).pack(side="left", padx=8)
        self.after(120, self.lift)

    def _copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.text)
        self.msg.configure(text="Relatório copiado para a área de transferência.")

    def _save(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".txt", filetypes=[("Texto", "*.txt")],
                                            initialfile=time.strftime("relatorio_smart_gaming_manager_%Y%m%d_%H%M.txt"))
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.text)
        except OSError as exc:
            self.msg.configure(text=f"Não foi possível salvar: {exc}")
            return
        self.msg.configure(text=f"Salvo em: {path}")