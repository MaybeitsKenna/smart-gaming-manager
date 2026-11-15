"""Smart Gaming Manager - ponto de entrada.
Se algo falhar ao iniciar (o .exe não tem janela de terminal), mostra o erro numa caixa de mensagem e copia o texto."""
import sys
import traceback


def _fatal(text: str) -> None:
    try:
        import tkinter
        import tkinter.messagebox
        root = tkinter.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        tkinter.messagebox.showerror("Smart Gaming Manager - erro ao iniciar",
                                     "O programa não conseguiu iniciar. O texto abaixo foi copiado: cole na conversa "
                                     "de suporte.\n\n" + text[-1500:])
    except Exception:
        pass
    sys.exit(1)


if __name__ == "__main__":
    try:
        from sgm.support import sanitize
        from sgm.ui.app import App
        App().mainloop()
    except Exception:
        text = traceback.format_exc()
        try:
            from sgm.support import sanitize
            text = sanitize(text)
        except Exception:
            pass
        _fatal(text)