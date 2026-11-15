"""Verificação de assinatura digital (Authenticode) - SOMENTE LEITURA.

Usa o Get-AuthenticodeSignature do Windows PowerShell, que entende tanto assinaturas embutidas
quanto assinaturas por catálogo (usadas pela maioria dos arquivos do Windows).
Uma única chamada verifica todos os caminhos de uma vez. Não altera nada no sistema.

Se a verificação falhar, o motivo fica em LAST_ERROR (o main_cli mostra na tela)."""
from __future__ import annotations
import base64
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Iterable, Optional
import ntpath

LAST_ERROR: str = ""


@dataclass(frozen=True)
class SigInfo:
    status: str                 # "Valid", "NotSigned", "HashMismatch", "NotTrusted", "Error", ...
    subject: Optional[str]      # subject do certificado (ex.: "CN=Microsoft Corporation, O=...")


# O resultado é gravado em arquivo (SGM_OUT) em UTF-8, sem depender do console/codificação.
_PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
  Import-Module Microsoft.PowerShell.Security
  $paths = @(Get-Content -LiteralPath $env:SGM_LIST -Encoding UTF8 | Where-Object { $_ })
  $out = New-Object System.Collections.Generic.List[object]
  foreach ($item in $paths) {
    $p = [string]$item
    try {
      $s = Get-AuthenticodeSignature -LiteralPath $p
      $out.Add([pscustomobject]@{ path = $p; status = [string]$s.Status; subject = $s.SignerCertificate.Subject })
    } catch {
      $out.Add([pscustomobject]@{ path = $p; status = 'Error'; subject = $null })
    }
  }
  $json = ConvertTo-Json -InputObject @($out.ToArray()) -Compress
  [System.IO.File]::WriteAllText($env:SGM_OUT, $json, (New-Object System.Text.UTF8Encoding($false)))
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
"""


def norm_path(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path))


def signer_name(subject: Optional[str]) -> Optional[str]:
    """Extrai o nome (CN) do subject do certificado."""
    if not subject:
        return None
    m = re.search(r'CN=(?:"([^"]+)"|([^,]+))', subject)
    if not m:
        return subject
    return (m.group(1) or m.group(2)).strip()


def _powershell_exe() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    full = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return full if os.path.exists(full) else "powershell.exe"


def verify_signatures(paths: Iterable[str], timeout: int = 180) -> dict[str, SigInfo]:
    """Retorna {caminho_normalizado: SigInfo}. Se falhar, devolve {} e preenche LAST_ERROR."""
    global LAST_ERROR
    LAST_ERROR = ""
    if os.name != "nt":
        LAST_ERROR = "Sistema não é Windows."
        return {}
    unique = sorted({p for p in paths if p})
    if not unique:
        return {}
    tmp_dir = tempfile.mkdtemp(prefix="sgm_")
    list_path = os.path.join(tmp_dir, "paths.json")
    out_path = os.path.join(tmp_dir, "result.json")
    try:
        with open(list_path, "w", encoding="utf-8") as f:
            f.write("\n".join(unique))
        encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
        env = dict(os.environ, SGM_LIST=list_path, SGM_OUT=out_path)
        env.pop("PSModulePath", None)       # evita conflito quando o terminal usa PowerShell 7
        proc = subprocess.run(
            [_powershell_exe(), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if not os.path.exists(out_path):
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            LAST_ERROR = f"PowerShell terminou com código {proc.returncode} e não gerou resultado. Erro: {err[:600] or '(vazio)'}"
            return {}
        with open(out_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if isinstance(data, dict):                  # formato alternativo do PowerShell 5.1: {"value": [...], "Count": N}
            data = data.get("value") or [data]
        result: dict[str, SigInfo] = {}
        for item in data:
            raw_path = item.get("path")
            if isinstance(raw_path, dict):          # formato alternativo do PowerShell 5.1
                raw_path = raw_path.get("value") or raw_path.get("PSPath")
            if not isinstance(raw_path, str) or not raw_path:
                continue
            subject = item.get("subject")
            if not isinstance(subject, str):
                subject = None
            result[norm_path(raw_path)] = SigInfo(str(item.get("status") or "Unknown"), subject)
        return result
    except Exception as exc:
        LAST_ERROR = f"{type(exc).__name__}: {exc}"
        return {}
    finally:
        for fp in (list_path, out_path):          # apaga só os arquivos temporários criados por este programa
            try:
                os.remove(fp)
            except OSError:
                pass
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass