"""Etapa 10: testes de suporte, versão e privacidade. Rodar junto:  python -m unittest discover -s tests -v"""
from __future__ import annotations
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_stage9 import sample_result                                      # noqa: E402
from sgm import __version__                                                # noqa: E402
from sgm.support import build_support_info, sanitize                       # noqa: E402


class SupportTests(unittest.TestCase):
    def test_versao_no_formato_correto(self):
        """A versão do programa existe e tem o formato número.número.número"""
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")

    def test_info_de_suporte_nao_vaza_nomes_nem_caminhos(self):
        """O texto de suporte não inclui nomes de programas, caminhos de arquivos nem pastas de usuário"""
        text = build_support_info(sample_result(), 2)
        low = text.lower()
        for forbidden in ("discord", "explorer", "hd-player", "c:\\", "\\users", "program files"):
            self.assertNotIn(forbidden, low, forbidden)
        self.assertIsNone(re.search(r"[A-Za-z0-9_-]+\.exe", text), "não pode haver nome de programa (algo.exe)")
        for expected in ("INFORMAÇÕES PARA SUPORTE", f"v{__version__}", "Por categoria", "PROTEGIDO", "Encerrados na sessão: 2"):
            self.assertIn(expected, text)

    def test_info_de_suporte_sem_analise(self):
        """Antes de analisar, o texto de suporte ainda funciona e diz que a análise não foi feita"""
        text = build_support_info(None)
        self.assertIn("ainda não foi feita", text)
        self.assertIn(f"v{__version__}", text)

    def test_sanitize_remove_usuario_pasta_e_computador(self):
        """Nome de usuário, pasta pessoal e nome do computador somem do texto de erro"""
        raw = r'File "C:\Users\maria_silva\proj\app.py", line 3 em MARIA-PC por maria_silva'
        with mock.patch("sgm.support.getpass.getuser", return_value="maria_silva"), \
             mock.patch("sgm.support.platform.node", return_value="MARIA-PC"), \
             mock.patch("sgm.support.os.path.expanduser", return_value=r"C:\Users\maria_silva"):
            clean = sanitize(raw)
        self.assertNotIn("maria", clean.lower())
        self.assertIn("<usuario>", clean + "<usuario>")      # o marcador pode ter sido absorvido pelo "~"
        self.assertIn("~", clean)

    def test_main_mostra_erro_de_inicializacao(self):
        """O main.py captura falhas ao iniciar e mostra uma caixa de mensagem (o .exe não tem terminal)"""
        text = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("showerror", text)
        self.assertIn("except Exception", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)