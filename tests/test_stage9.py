"""Etapa 9: testes do relatório e de pontos específicos do empacotamento.
Rodar junto com os outros:  python -m unittest discover -s tests -v"""
from __future__ import annotations
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_safety import P, classify, sig                                  # noqa: E402
from sgm.classifier import Category                                       # noqa: E402
from sgm.gaming import GamingSession                                      # noqa: E402
from sgm.knowledge import build_groups                                    # noqa: E402
from sgm.models import SystemSnapshot                                     # noqa: E402
from sgm.report import build_report                                       # noqa: E402
from sgm.service import AnalysisResult                                    # noqa: E402
from sgm.terminator import ActionRecord                                   # noqa: E402


def sample_result():
    procs = [P(1, "HD-Player.exe", r"C:\Program Files\BlueStacks_msi5\HD-Player.exe", ram=3000, cpu=30),
             P(2, "explorer.exe", r"C:\Windows\explorer.exe", ram=250),
             P(3, "discord.exe", r"C:\Users\usuario\AppData\Local\Discord\discord.exe", ram=1000, cpu=4,
               company="Discord Inc.", desc="Discord")]
    sigs = sig(procs[2].exe_path, "Valid", 'CN="Discord Inc."')
    cls = classify(procs, sigs)
    return AnalysisResult(SystemSnapshot(20, 16000, 12000, 4000, 3, procs), cls, build_groups(procs, cls), "")


class ReportTests(unittest.TestCase):
    def test_relatorio_completo_com_acoes(self):
        """O relatório traz todas as seções pedidas, os aplicativos encerrados, o aviso de forçado e o aviso de FPS"""
        base = GamingSession(started=1000.0, before_cpu=84.0, before_used_mb=12000, before_avail_mb=4000, actions_start=0)
        acts = [ActionRecord("brave.exe", "normal", 10, 950.0, 11.0, 1100.0, "Navegador Brave.", "As abas fecham."),
                ActionRecord("Discord.exe", "forçado", 6, 1000.0, 4.0, 1200.0, "Chat.", "Você sai das chamadas.")]
        text = build_report(base, acts, sample_result(), 40.0, 9000.0, 7000.0, 16000.0, now=2000.0)
        for part in ("RESUMO", "ANTES E DEPOIS", "APLICATIVOS ENCERRADOS", "APLICATIVOS MANTIDOS",
                     "POSSÍVEIS IMPACTOS", "AVISOS IMPORTANTES", "brave.exe", "Discord.exe", "As abas fecham.",
                     "Encerrados à força", "NÃO garante aumento de FPS", "Aplicativos encerrados : 2 (16 processos)",
                     "+3000 MB"):
            self.assertIn(part, text)

    def test_relatorio_sem_acoes(self):
        """Sem nenhum encerramento, o relatório diz isso com clareza"""
        base = GamingSession(1000.0, 20.0, 12000, 4000, 0)
        text = build_report(base, [], sample_result(), 20.0, 12000.0, 4000.0, 16000.0, now=2000.0)
        self.assertIn("Nenhum aplicativo foi encerrado nesta sessão", text)
        self.assertIn("NÃO garante aumento de FPS", text)

    def test_relatorio_lista_protegidos_e_opcionais_mantidos(self):
        """O relatório lista o que ficou protegido e os opcionais que continuam abertos"""
        base = GamingSession(1000.0, 20.0, 12000, 4000, 0)
        text = build_report(base, [], sample_result(), 20.0, 12000.0, 4000.0, 16000.0, now=2000.0)
        self.assertIn("Protegidos automaticamente", text)
        self.assertIn("discord.exe", text)


class PackagingAndFileWriteTests(unittest.TestCase):
    def _tree(self, rel):
        return ast.parse((ROOT / rel).read_text(encoding="utf-8"))

    def test_openconsole_e_protegido(self):
        """O OpenConsole (host de terminal) nunca é encerrável, para não derrubar o terminal deste programa"""
        path = r"C:\Program Files\Microsoft VS Code\resources\OpenConsole.exe"
        procs = [P(1, "OpenConsole.exe", path, company="Microsoft Corporation", desc="Console Window and PTY Host")]
        c = classify(procs, sig(path, "Valid", "CN=Microsoft Corporation"))[1]
        self.assertEqual(c.category, Category.PROTEGIDO)

    def test_subprocess_nao_herda_entrada_do_console(self):
        """A chamada ao PowerShell define stdin (sem isso o .exe sem console falha com WinError 6)"""
        found = False
        for node in ast.walk(self._tree("sgm/signature.py")):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                found = True
                self.assertIn("stdin", {k.arg for k in node.keywords})
        self.assertTrue(found)

    def test_escrita_de_arquivos_so_onde_permitido(self):
        """Só dois lugares abrem arquivos para escrita: a lista temporária das assinaturas e o SALVAR do relatório"""
        allowed = {"signature.py", "report_window.py"}
        problems = []
        for f in sorted((ROOT / "sgm").rglob("*.py")):
            for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call):
                    fn = node.func
                    name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else None
                    if name in ("write_text", "write_bytes") and f.name not in allowed:
                        problems.append(f"{f.name}:{node.lineno} usa {name}")
                    if name == "open":
                        mode = None
                        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                            mode = node.args[1].value
                        for k in node.keywords:
                            if k.arg == "mode" and isinstance(k.value, ast.Constant):
                                mode = k.value.value
                        if mode and any(c in str(mode) for c in "wax+") and f.name not in allowed:
                            problems.append(f"{f.name}:{node.lineno} abre arquivo para escrita")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_salvar_relatorio_so_com_clique(self):
        """O relatório só é gravado em arquivo dentro do botão SALVAR (método _save da janela do relatório)"""
        tree = self._tree("sgm/ui/report_window.py")
        writers = []
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            for fn in [n for n in cls.body if isinstance(n, ast.FunctionDef)]:
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                        writers.append(f"{cls.name}.{fn.name}")
        self.assertEqual(writers, ["ReportWindow._save"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
    