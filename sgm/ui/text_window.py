"""Janela simples com texto para COPIAR (erros e informações de suporte). Não grava nada em disco."""
from __future__ import annotations

import customtkinter as ctk


class TextCopyWindow(ctk.CTkToplevel):
    def __init__(self, app, title: str, text: str, intro: str = "") -> None:
        super().__init__(app)
        self.text = text
        self.title(title)
        self.geometry("820x600")
        if intro:
            ctk.CTkLabel(self, text=intro, wraplength=780, justify="left", anchor="w",
                         text_color="gray75").pack(fill="x", padx=16, pady=(14, 4))
        box = ctk.CTkTextbox(self, wrap="word", font=ctk.CTkFont(family="Consolas", size=13))
        box.pack(fill="both", expand=True, padx=14, pady=(8, 8))
        box.insert("1.0", text)
        box.configure(state="disabled")
        self.msg = ctk.CTkLabel(self, text="", text_color="gray70")
        self.msg.pack(pady=(0, 4))
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(pady=(0, 14))
        ctk.CTkButton(bar, text="COPIAR", width=170, command=self._copy).pack(side="left", padx=8)
        ctk.CTkButton(bar, text="FECHAR", width=150, fg_color="gray30", command=self.destroy).pack(side="left", padx=8)
        self.after(120, self.lift)

    def _copy(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self.text)
        self.msg.configure(text="Copiado! Agora é só colar na conversa.")