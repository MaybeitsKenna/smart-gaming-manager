"""Etapa 8: testes de segurança do Smart Gaming Manager.

Como rodar (na pasta do projeto, com o venv ativo):
    python -m unittest discover -s tests -v

Nenhum teste encerra processos reais além dos que ELE MESMO cria (processos de teste que dormem).
Não mexe em Registro, serviços, arquivos do usuário ou configurações."""
from __future__ import annotations
import ast
import dataclasses
import random
import subprocess
import sys
import time
import unittest
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sgm import terminator as T                                   # noqa: E402
from sgm.classifier import Category, classify_all                 # noqa: E402
from sgm.gaming import candidates, detect_emulators               # noqa: E402
from sgm.invariants import violations                             # noqa: E402
from sgm.knowledge import APP_INFO, AppGroup, Explanation, build_groups   # noqa: E402
from sgm.models import FileMeta, ProcessInfo, SystemSnapshot      # noqa: E402
from sgm.signature import SigInfo, norm_path                      # noqa: E402

ME = "pc\\usuario"
USER = "PC\\usuario"


def P(pid, name, path, user=USER, company=None, desc=None, product=None, ppid=None, pname=None,
      ram=10.0, cpu=0.0, denied=False, ctime=0.0):
    return ProcessInfo(pid, name, path, True, user, ppid, pname, ctime, cpu, ram, False,
                       FileMeta(company=company, description=desc, product=product), denied)


def classify(procs, sigs=None):
    return classify_all(procs, sigs or {}, set(), me=ME)


def sig(path, status="Valid", subject="CN=Fake"):
    return {norm_path(path): SigInfo(status, subject)}


def cat(procs, index=0, sigs=None):
    return classify(procs, sigs)[procs[index].pid].category


def fake_group(infos, category=Category.SEGURO, can_close=True, tags=None, key=None):
    ex = Explanation("teste", "1%", "imp", "efeito", "rec", [])
    return AppGroup(key or norm_path(infos[0].exe_path or "x"), infos[0].name, infos, category, False, 1.0, 1.0,
                    False, can_close, ex, set(tags or ()))


# ======================================================================================== 1) AUDITORIA DO CÓDIGO
class StaticAuditTests(unittest.TestCase):
    """O código-fonte não contém operações proibidas (lido com análise de sintaxe, sem executar nada)."""

    RULES = [
        ("escrever/apagar no Registro", {"SetValue", "SetValueEx", "CreateKey", "CreateKeyEx", "DeleteKey",
                                          "DeleteKeyEx", "DeleteValue", "SaveKey", "LoadKey"}, set()),
        ("encerrar processos ou enviar mensagens a janelas", {"kill", "terminate", "TerminateProcess",
                                                                "TerminateThread", "PostMessageW", "SendMessageW"},
         {"terminator.py"}),
        ("apagar arquivos", {"remove", "unlink", "rmdir", "rmtree", "removedirs"}, {"signature.py"}),
        ("executar comandos externos", {"system", "popen", "Popen", "run", "call", "check_call", "check_output",
                                         "startfile", "spawnl", "spawnv"}, {"signature.py"}),
        ("mudar prioridade, afinidade ou suspender processos", {"nice", "ionice", "suspend", "resume",
                                                                  "SetPriorityClass", "cpu_affinity"}, set()),
        ("controlar serviços do Windows", {"win_service_iter", "win_service_get", "StartService", "ControlService",
                                            "DeleteService", "ChangeServiceConfig", "ChangeServiceConfig2"}, set()),
        ("executar código dinâmico", {"eval", "exec", "__import__"}, set()),
    ]
    FORBIDDEN_IMPORTS = {"socket", "requests", "urllib", "http", "ftplib", "smtplib", "telnetlib", "webbrowser",
                         "pickle", "marshal"}
    CTYPES_ALLOWED = {"winmeta.py", "terminator.py"}

    def _files(self):
        return sorted((ROOT / "sgm").rglob("*.py"))

    def test_nenhuma_chamada_proibida(self):
        """Nenhuma chamada proibida (Registro, serviços, apagar, prioridade, comandos) fora dos arquivos permitidos"""
        problems = []
        for f in self._files():
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                called = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else None
                for label, names, allowed in self.RULES:
                    if called in names and f.name not in allowed:
                        problems.append(f"{f.name}:{node.lineno} usa '{called}' ({label})")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_sem_rede_nem_modulos_perigosos(self):
        """O programa não importa nada de rede nem módulos de execução arriscada"""
        problems = []
        for f in self._files():
            for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods = [node.module.split(".")[0]]
                problems += [f"{f.name}: importa '{m}'" for m in mods if m in self.FORBIDDEN_IMPORTS]
        self.assertEqual(problems, [], "\n".join(problems))

    def test_registro_somente_leitura(self):
        """O Registro só é aberto para leitura (KEY_READ), nunca com permissão de escrita"""
        for f in self._files():
            text = f.read_text(encoding="utf-8")
            self.assertNotIn("KEY_WRITE", text, f.name)
            self.assertNotIn("KEY_ALL_ACCESS", text, f.name)
            self.assertNotIn("KEY_SET_VALUE", text, f.name)
        self.assertIn("KEY_READ", (ROOT / "sgm" / "startup.py").read_text(encoding="utf-8"))

    def test_ctypes_so_onde_necessario(self):
        """ctypes (chamadas nativas do Windows) só em winmeta.py e terminator.py"""
        problems = []
        for f in self._files():
            if f.name in self.CTYPES_ALLOWED:
                continue
            if "ctypes" in f.read_text(encoding="utf-8"):
                problems.append(f.name)
        self.assertEqual(problems, [])

    def test_unico_comando_externo_e_a_verificacao_de_assinatura(self):
        """O único comando externo é o Get-AuthenticodeSignature (somente leitura)"""
        text = (ROOT / "sgm" / "signature.py").read_text(encoding="utf-8")
        self.assertIn("Get-AuthenticodeSignature", text)
        for bad in ("Remove-Item", "Set-ItemProperty", "Stop-Process", "Stop-Service", "Set-Service",
                    "Disable-", "Invoke-Expression", "Start-Process", "New-ItemProperty", "reg add", "reg delete"):
            self.assertNotIn(bad, text)


# ======================================================================================== 2) CLASSIFICADOR
class ClassifierSafetyTests(unittest.TestCase):
    def test_sem_nenhuma_assinatura_nada_e_encerravel(self):
        """Se a verificação de assinaturas falhar por completo, NADA vira SEGURO ou ATENÇÃO"""
        procs = [P(1, "discord.exe", r"C:\Users\usuario\AppData\Local\Discord\discord.exe", company="Discord Inc.",
                   desc="Discord"),
                 P(2, "brave.exe", r"C:\Program Files\Brave\brave.exe", company="Brave Software", desc="Brave"),
                 P(3, "Code.exe", r"C:\Users\usuario\AppData\Local\Programs\VS\Code.exe", company="Microsoft Corporation",
                   desc="VS Code"),
                 P(4, "qualquer.exe", r"C:\Users\usuario\Downloads\qualquer.exe", company="Foo", desc="Foo")]
        for c in classify(procs, {}).values():
            self.assertNotIn(c.category, (Category.SEGURO, Category.ATENCAO), c.reason)

    def test_nome_do_windows_fora_da_pasta_e_suspeito(self):
        """svchost.exe (ou lsass, explorer...) fora da pasta do Windows vira DESCONHECIDO com alerta"""
        for name in ("svchost.exe", "lsass.exe", "explorer.exe", "csrss.exe", "winlogon.exe", "audiodg.exe"):
            procs = [P(1, name, rf"C:\Users\usuario\AppData\Local\Temp\{name}")]
            c = classify(procs)[1]
            self.assertEqual(c.category, Category.DESCONHECIDO, name)
            self.assertIn("suspect", c.tags, name)

    def test_arquivo_na_pasta_do_windows_e_protegido(self):
        """Qualquer arquivo dentro da pasta do Windows é PROTEGIDO"""
        procs = [P(1, "qualquer.exe", r"C:\Windows\System32\qualquer.exe", company="Foo", desc="Foo")]
        self.assertEqual(cat(procs, sigs=sig(procs[0].exe_path)), Category.PROTEGIDO)

    def test_app_conhecido_com_assinante_errado_nao_e_seguro(self):
        """Discord com assinatura válida, mas de outra empresa, NÃO é SEGURO"""
        path = r"C:\Users\usuario\AppData\Local\Discord\discord.exe"
        procs = [P(1, "discord.exe", path, company="Evil Corp", desc="Discord")]
        c = classify(procs, sig(path, "Valid", "CN=Evil Corp"))[1]
        self.assertEqual(c.category, Category.DESCONHECIDO)
        self.assertIn("suspect", c.tags)

    def test_app_conhecido_sem_assinatura_nao_e_seguro(self):
        """Discord falso (sem assinatura) em pasta temporária NÃO é SEGURO"""
        path = r"C:\Users\usuario\AppData\Local\Temp\discord.exe"
        procs = [P(1, "discord.exe", path, company="Discord Inc.", desc="Discord")]
        self.assertEqual(cat(procs, sigs=sig(path, "NotSigned", None)), Category.DESCONHECIDO)

    def test_assinatura_invalida_e_suspeita(self):
        """Arquivo adulterado (HashMismatch) vira DESCONHECIDO suspeito"""
        path = r"C:\Program Files\Foo\foo.exe"
        procs = [P(1, "foo.exe", path, company="Foo", desc="Foo")]
        c = classify(procs, sig(path, "HashMismatch", "CN=Foo"))[1]
        self.assertEqual(c.category, Category.DESCONHECIDO)
        self.assertIn("suspect", c.tags)

    def test_dono_diferente_ou_sem_caminho_e_protegido(self):
        """Processo de outro usuário/serviço, sem dono legível ou sem caminho é PROTEGIDO"""
        self.assertEqual(cat([P(1, "x.exe", r"C:\Foo\x.exe", user="NT AUTHORITY\\SYSTEM")]), Category.PROTEGIDO)
        self.assertEqual(cat([P(1, "x.exe", r"C:\Foo\x.exe", user=None)]), Category.PROTEGIDO)
        self.assertEqual(cat([P(1, "x.exe", None, denied=True)]), Category.PROTEGIDO)

    def test_emulador_protegido_pelo_nome_mesmo_sem_assinatura(self):
        """Emulador (vários nomes) é PROTEGIDO sem precisar de assinatura"""
        for name, path in [("HD-Player.exe", r"C:\Program Files\BlueStacks_msi5\HD-Player.exe"),
                           ("dnplayer.exe", r"C:\LDPlayer\LDPlayer9\dnplayer.exe"),
                           ("MEmu.exe", r"C:\Program Files\Microvirt\MEmu\MEmu.exe"),
                           ("Nox.exe", r"C:\Program Files\Nox\bin\Nox.exe"),
                           ("AndroidEmulatorEx.exe", r"C:\Program Files\TxGameAssistant\AndroidEmulatorEx.exe"),
                           ("adb.exe", r"C:\platform-tools\adb.exe")]:
            self.assertEqual(cat([P(1, name, path)]), Category.PROTEGIDO, name)

    def test_filho_do_emulador_e_protegido(self):
        """Processo filho de um processo do emulador também é protegido"""
        procs = [P(1, "HD-Player.exe", r"C:\Program Files\BlueStacks_msi5\HD-Player.exe"),
                 P(2, "ajudante.exe", r"C:\Program Files\Foo\ajudante.exe", ppid=1, pname="HD-Player.exe",
                   company="Foo", desc="Ajudante")]
        res = classify(procs, sig(procs[1].exe_path))
        self.assertEqual(res[2].category, Category.PROTEGIDO)

    def test_audio_rede_e_entrada_protegidos(self):
        """Áudio, rede/VPN e dispositivos de entrada são PROTEGIDOS"""
        for name, desc in [("RtkAudUService64.exe", "Realtek Audio Service"), ("vpnclient.exe", "VPN Client"),
                           ("wifi.exe", "Wi-Fi Manager"), ("GameInputSvc.exe", "GameInput")]:
            self.assertEqual(cat([P(1, name, rf"C:\Program Files\Foo\{name}", desc=desc)]), Category.PROTEGIDO, name)

    def test_propriedade_aleatoria_4000_processos(self):
        """4000 processos aleatórios: nenhuma regra de proteção é quebrada (invariantes)"""
        rng = random.Random(20261110)
        names = ["svchost.exe", "explorer.exe", "discord.exe", "brave.exe", "HD-Player.exe", "BstkSVC.exe", "nox.exe",
                 "dnplayer.exe", "audiodg.exe", "chrome.exe", "steam.exe", "qualquer.exe", "RtkAudUService64.exe",
                 "ProtonVPNService.exe", "MsMpEng.exe", "lsass.exe", "Code.exe", "adb.exe", "GameInputSvc.exe",
                 "pet.exe", "helper.exe", "claude.exe", "spotify.exe", "OpenConsole.exe"]
        dirs = [r"C:\Windows\System32", r"C:\Program Files\App", r"C:\Users\usuario\AppData\Local\Temp",
                r"C:\Program Files\BlueStacks_msi5", r"C:\Program Files\WindowsApps\Pkg", None,
                r"C:\Users\usuario\Downloads", r"C:\ProgramData\Microsoft\Windows Defender"]
        users = [USER, USER, USER, "NT AUTHORITY\\SYSTEM", None, "PC\\outro"]
        companies = [None, "Microsoft Corporation", "Discord Inc.", "Brave Software", "BlueStack Systems", "Evil Corp",
                     "Realtek Semiconductor Corp.", "Valve Corporation", "Anthropic", "Spotify AB"]
        descs = [None, "Discord", "Realtek Audio Service", "VPN Client", "Helper tool", "MSI App Player", "Brave"]
        statuses = ["Valid", "Valid", "NotSigned", "HashMismatch", "UnknownError", None]
        signers = ["CN=Microsoft Corporation", 'CN="Discord Inc."', "CN=Evil", "CN=Brave Software, Inc.", "CN=Valve",
                   "CN=Anthropic PBC", "CN=Spotify AB"]
        procs, sigs = [], {}
        for pid in range(1, 4001):
            name = rng.choice(names)
            folder = rng.choice(dirs)
            path = None if folder is None else f"{folder}\\{name}"
            ppid = rng.randint(1, max(1, pid - 1)) if pid > 1 and rng.random() < 0.4 else None
            procs.append(P(pid, name, path, user=rng.choice(users), company=rng.choice(companies),
                           desc=rng.choice(descs), ppid=ppid, denied=rng.random() < 0.03))
            st = rng.choice(statuses)
            if path and st:
                sigs[norm_path(path)] = SigInfo(st, rng.choice(signers) if st != "NotSigned" else None)
        found = violations(procs, classify(procs, sigs), ME)
        self.assertEqual(found, [], "\n".join(found[:20]))


# ======================================================================================== 3) ENCERRAMENTO
def sleeper():
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(25)"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def live_info(popen, **overrides):
    pr = psutil.Process(popen.pid)
    data = dict(pid=pr.pid, name=pr.name(), exe_path=pr.exe(), cmdline_available=True, username=pr.username(),
                parent_pid=pr.ppid(), parent_name=None, create_time=pr.create_time(), cpu_percent=1.0, ram_mb=25.0,
                has_window=False, meta=FileMeta(), access_denied=False)
    data.update(overrides)
    return ProcessInfo(**data)


class TerminatorSafetyTests(unittest.TestCase):
    OWN = {999999}

    def _blocked(self, group):
        return T.prepare(group, own=self.OWN, me=ME).blocked

    def test_recusa_categorias_protegidas(self):
        """Grupos PROTEGIDO, DESCONHECIDO ou sem permissão de encerrar são recusados"""
        info = P(1, "x.exe", r"C:\Foo\x.exe")
        for category in (Category.PROTEGIDO, Category.DESCONHECIDO):
            self.assertTrue(self._blocked(fake_group([info], category=category, can_close=False)))
        self.assertTrue(self._blocked(fake_group([info], can_close=False)))

    def test_recusa_mesmo_se_o_classificador_errasse(self):
        """Defesa em camadas: perigos óbvios são recusados mesmo num grupo marcado como encerrável (bug simulado)"""
        danger = [
            P(1, "explorer.exe", r"C:\Users\usuario\x\explorer.exe"),
            P(2, "svchost.exe", r"C:\Users\usuario\x\svchost.exe"),
            P(3, "qualquer.exe", r"C:\Windows\System32\qualquer.exe"),
            P(4, "HD-Player.exe", r"C:\Program Files\BlueStacks_msi5\HD-Player.exe"),
            P(5, "x.exe", r"C:\Foo\x.exe", user="NT AUTHORITY\\SYSTEM"),
            P(6, "x.exe", r"C:\Foo\x.exe", user=None),
            P(7, "x.exe", None, denied=True),
            P(999999, "python.exe", r"C:\Python\python.exe"),
            P(8, "MsMpEng.exe", r"C:\Program Files\Windows Defender\MsMpEng.exe"),
        ]
        for info in danger:
            msg = self._blocked(fake_group([info]))
            self.assertIn("Bloqueado por segurança", msg, f"{info.name}: {msg}")

    def test_recusa_por_marca_de_protecao(self):
        """Grupo com qualquer marca de proteção do classificador é recusado"""
        info = P(1, "x.exe", r"C:\Foo\x.exe")
        for tag in sorted(T.PROTECTIVE_TAGS):
            msg = self._blocked(fake_group([info], tags={tag}))
            self.assertIn("Bloqueado por segurança", msg, tag)

    def test_recusa_se_um_unico_membro_for_perigoso(self):
        """Basta UM processo perigoso no grupo para o grupo inteiro ser recusado"""
        ok = P(1, "app.exe", r"C:\Foo\app.exe")
        bad = P(2, "app.exe", r"C:\Foo\app.exe", user="NT AUTHORITY\\SYSTEM")
        self.assertIn("Bloqueado por segurança", self._blocked(fake_group([ok, bad])))

    def test_encerramento_real_de_processo_de_teste(self):
        """Pedido normal sem janela não encerra; depois FORÇAR encerra o processo de teste que o próprio teste criou"""
        sp = sleeper()
        try:
            time.sleep(0.5)
            info = live_info(sp)
            group = fake_group([info])
            plan = T.prepare(group, own=self.OWN, me=psutil.Process().username())
            self.assertEqual(plan.blocked, "")
            self.assertEqual(len(plan.targets), 1)
            out = T.close_gracefully(plan, wait_seconds=1.5)
            if out.windows_signaled == 0:
                self.assertIsNone(sp.poll(), "sem janelas, o pedido normal não deve matar o processo")
            plan2 = T.prepare(group, own=self.OWN, me=psutil.Process().username())
            if plan2.targets:
                out2 = T.force_kill(plan2)
                self.assertEqual(out2.still_running, [])
            sp.wait(timeout=8)
            self.assertIsNotNone(sp.poll())
        finally:
            if sp.poll() is None:
                sp.kill()

    def test_revalida_numero_de_processo_reutilizado(self):
        """Se o número do processo agora é de outro programa (hora de criação diferente), nada é encerrado"""
        sp = sleeper()
        try:
            time.sleep(0.5)
            info = live_info(sp)
            stale = dataclasses.replace(info, create_time=info.create_time - 1000)
            plan = T.prepare(fake_group([stale]), own=self.OWN, me=psutil.Process().username())
            self.assertTrue(plan.blocked)
            self.assertIsNone(sp.poll(), "o processo atual NÃO pode ter sido encerrado")
        finally:
            sp.kill()
            sp.wait()

    def test_revalida_arquivo_diferente_e_processo_morto(self):
        """Arquivo executável diferente ou processo que já morreu: nada é encerrado"""
        sp = sleeper()
        try:
            time.sleep(0.5)
            info = live_info(sp)
            other = dataclasses.replace(info, exe_path=info.exe_path + ".outro")
            plan = T.prepare(fake_group([other], key=norm_path(other.exe_path)), own=self.OWN,
                             me=psutil.Process().username())
            self.assertTrue(plan.blocked)
            self.assertIsNone(sp.poll())
        finally:
            sp.kill()
            sp.wait()
        plan = T.prepare(fake_group([info]), own=self.OWN, me=psutil.Process().username())
        self.assertTrue(plan.blocked)

    def test_grupo_de_varios_processos(self):
        """Um grupo com 3 processos é encerrado por inteiro, um aplicativo por vez"""
        sps = [sleeper() for _ in range(3)]
        try:
            time.sleep(0.8)
            infos = [live_info(s) for s in sps]
            group = fake_group(infos, key=norm_path(infos[0].exe_path))
            plan = T.prepare(group, own=self.OWN, me=psutil.Process().username())
            self.assertEqual(len(plan.targets), 3)
            out = T.force_kill(plan)
            self.assertEqual(len(out.closed), 3)
        finally:
            for s in sps:
                if s.poll() is None:
                    s.kill()


# ======================================================================================== 4) EXPLICAÇÕES E GAMING MODE
class ExplanationAndGamingTests(unittest.TestCase):
    def test_desconhecido_diz_finalidade_nao_identificada(self):
        """Processo sem nenhuma informação mostra 'Finalidade não identificada'"""
        procs = [P(1, "misterio.exe", r"C:\Users\usuario\Downloads\misterio.exe")]
        group = build_groups(procs, classify(procs, sig(procs[0].exe_path, "NotSigned", None)))[0]
        self.assertIn("Finalidade não identificada", group.explanation.what)
        self.assertFalse(group.can_close)

    def test_discord_falso_nao_recebe_a_explicacao_do_discord(self):
        """O texto curado do Discord só vale para o Discord verificado, nunca pelo nome"""
        path = r"C:\Users\usuario\AppData\Local\Temp\discord.exe"
        procs = [P(1, "discord.exe", path)]
        group = build_groups(procs, classify(procs, sig(path, "NotSigned", None)))[0]
        self.assertNotEqual(group.explanation.what, APP_INFO["discord.exe"][0])
        self.assertTrue(group.explanation.recommendation.startswith("ALERTA") or "NÃO" in group.explanation.recommendation)

    def test_protegidos_sempre_dizem_nao_encerrar(self):
        """Todo grupo protegido ou desconhecido mostra recomendação de NÃO encerrar e não é encerrável"""
        procs = [P(1, "explorer.exe", r"C:\Windows\explorer.exe"), P(2, "x.exe", None, denied=True),
                 P(3, "HD-Player.exe", r"C:\Program Files\BlueStacks_msi5\HD-Player.exe")]
        for g in build_groups(procs, classify(procs)):
            self.assertFalse(g.can_close, g.name)
            self.assertIn("NÃO", g.explanation.recommendation + "Finalidade não identificada".upper())

    def test_candidatos_do_gaming_mode_so_incluem_encerraveis(self):
        """A lista 'Maiores consumidores' nunca inclui emulador, Windows ou processos protegidos"""
        procs = [P(1, "HD-Player.exe", r"C:\Program Files\BlueStacks_msi5\HD-Player.exe", ram=3000, cpu=40),
                 P(2, "explorer.exe", r"C:\Windows\explorer.exe", ram=500, cpu=5),
                 P(3, "brave.exe", r"C:\Program Files\Brave\brave.exe", ram=900, cpu=10, company="Brave Software",
                   desc="Brave")]
        sigs = sig(procs[2].exe_path, "Valid", "CN=Brave Software, Inc.")
        groups = build_groups(procs, classify(procs, sigs))
        names = [g.name for g in candidates(groups)]
        self.assertEqual(names, ["brave.exe"])

    def test_detecta_emulador_e_filhos(self):
        """O emulador e seus filhos são detectados como uma família"""
        procs = [P(1, "HD-Player.exe", r"C:\Program Files\BlueStacks_msi5\HD-Player.exe", company="BlueStack Systems",
                   desc="MSI App Player"),
                 P(2, "BstkSVC.exe", r"C:\Program Files\BlueStacks_msi5\BstkSVC.exe")]
        emus = detect_emulators(SystemSnapshot(0, 0, 0, 0, 2, procs), classify(procs))
        self.assertEqual(len(emus), 1)
        self.assertEqual(emus[0].process_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
    