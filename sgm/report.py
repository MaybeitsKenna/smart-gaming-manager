"""Etapa 9: relatório final. Só monta TEXTO a partir de dados já coletados. Não encerra nem altera nada."""
from __future__ import annotations
import time
from typing import Optional

from .gaming import GamingSession, candidates, mixed_protected_names, protection_summary
from .service import AnalysisResult
from .terminator import ActionRecord


def _gb(mb: float) -> str:
    return f"{mb / 1024:.1f} GB"


def _hm(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


def build_report(base: GamingSession, actions: list[ActionRecord], result: AnalysisResult, cpu_now: float,
                 used_now_mb: float, avail_now_mb: float, total_mb: float, now: Optional[float] = None) -> str:
    now = time.time() if now is None else now
    closed_procs = sum(a.closed_count for a in actions)
    closed_ram = sum(a.ram_mb for a in actions)
    closed_cpu = sum(a.cpu_percent for a in actions)
    forced = [a for a in actions if a.method == "forçado"]
    L: list[str] = []

    L += ["SMART GAMING MANAGER - RELATÓRIO",
          f"Gerado em: {time.strftime('%d/%m/%Y %H:%M', time.localtime(now))}",
          "=" * 64, "", "RESUMO",
          f"  Aplicativos encerrados : {len(actions)} ({closed_procs} processos)",
          f"  RAM que eles usavam    : ~{closed_ram:.0f} MB (soma medida na análise)",
          f"  CPU que eles usavam    : ~{closed_cpu:.1f}% (soma medida na análise)", ""]

    L += ["ANTES E DEPOIS (medidos no computador)",
          f"  Antes (às {_hm(base.started)}, ao iniciar a sessão):",
          f"    CPU {base.before_cpu:.0f}%  |  RAM em uso {_gb(base.before_used_mb)}  |  "
          f"RAM disponível {_gb(base.before_avail_mb)}",
          f"  Agora (às {_hm(now)}, CPU = média de 5 segundos):",
          f"    CPU {cpu_now:.0f}%  |  RAM em uso {_gb(used_now_mb)}  |  RAM disponível {_gb(avail_now_mb)}",
          f"  Variação: RAM disponível {avail_now_mb - base.before_avail_mb:+.0f} MB  |  "
          f"CPU {cpu_now - base.before_cpu:+.0f} pontos percentuais  |  RAM total do PC {_gb(total_mb)}",
          "  Estas medidas incluem TUDO que mudou no computador, não só o que este programa encerrou.",
          "  O que este programa encerrou está listado logo abaixo.", ""]

    L.append("APLICATIVOS ENCERRADOS")
    if not actions:
        L.append("  Nenhum aplicativo foi encerrado nesta sessão.")
    for i, a in enumerate(actions, 1):
        how = "pedido normal de fechamento" if a.method == "normal" else "encerrado à força"
        L.append(f"  {i}. {a.name} - {a.closed_count} processo(s) - {how} - às {_hm(a.when)}")
        L.append(f"     usava ~{a.ram_mb:.0f} MB de RAM e ~{a.cpu_percent:.1f}% de CPU na análise")
    L.append("")

    L.append("APLICATIVOS MANTIDOS")
    summary = protection_summary(result.snapshot, result.classifications)
    if summary:
        total = sum(n for _, n, _ in summary)
        L.append(f"  Protegidos automaticamente: {total} processos - " + ", ".join(f"{lab} {n}" for lab, n, _ in summary))
    mixed = mixed_protected_names(result.groups)
    if mixed:
        L.append(f"  Mantidos inteiros por terem partes protegidas: {', '.join(mixed)}")
    remaining = candidates(result.groups)
    if remaining:
        L.append(f"  Opcionais que continuam abertos ({len(remaining)}), por sua escolha:")
        for g in remaining[:10]:
            L.append(f"    - {g.name}: {g.ram_mb:.0f} MB de RAM, {g.cpu_percent:.1f}% de CPU")
        if len(remaining) > 10:
            L.append(f"    ... e mais {len(remaining) - 10}")
    else:
        L.append("  Nenhum aplicativo opcional relevante continua aberto.")
    L.append("")

    L.append("POSSÍVEIS IMPACTOS")
    for a in actions:
        L.append(f"  - {a.name}: {a.side_effects or 'apenas o próprio aplicativo deixou de funcionar até ser aberto de novo.'}")
    if forced:
        L.append("  - Encerrados à força: " + ", ".join(a.name for a in forced) +
                 ". Dados não salvos neles podem ter sido perdidos.")
    L += ["  - Todos os aplicativos podem ser abertos de novo normalmente.",
          "  - Nada foi desinstalado, apagado ou alterado: nem Registro, serviços, drivers, prioridades ou configurações.", ""]

    L += ["AVISOS IMPORTANTES",
          "  - Reduzir o uso de RAM ou CPU NÃO garante aumento de FPS.",
          "  - A CPU oscila bastante; compare com cautela. Outros programas também mudam o resultado.",
          "  - O Free Fire roda dentro do emulador; este programa não enxerga dentro dele nem confirma se o jogo está aberto."]
    return "\n".join(L)