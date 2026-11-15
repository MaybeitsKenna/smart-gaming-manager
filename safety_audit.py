"""Etapa 8: auditoria de segurança no SEU PC. SOMENTE LEITURA: nada é encerrado.

O que faz:
  1) Analisa o computador de verdade (mesma análise do programa).
  2) Confere as regras de proteção em todos os processos reais (invariantes).
  3) Tenta "planejar" o encerramento de TODOS os aplicativos protegidos, como se o classificador tivesse errado,
     e confirma que as travas independentes recusam todos.
  4) Mostra a lista de tudo que o programa deixaria você encerrar, com as evidências, para você revisar.

Uso:  python safety_audit.py"""
from __future__ import annotations
import dataclasses
import sys

from sgm.classifier import Category
from sgm.invariants import violations
from sgm.service import analyze
from sgm.terminator import current_user, own_pids, prepare


def main() -> int:
    print("Analisando o computador (10 a 30 segundos)...")
    res = analyze()
    snap, cls, groups = res.snapshot, res.classifications, res.groups
    me = current_user()
    own = own_pids()
    failures = 0

    print(f"\nProcessos: {snap.process_count}  |  Aplicativos (grupos): {len(groups)}  |  Usuário: {me}")
    if res.signature_error:
        print(f"AVISO: assinaturas não verificadas ({res.signature_error}). Tudo ficou mais restrito.")

    # 1) invariantes sobre os processos reais
    bad = violations(snap.processes, cls, me)
    print(f"\n[1] Regras de proteção em {snap.process_count} processos reais: "
          f"{'OK' if not bad else f'{len(bad)} VIOLAÇÃO(ÕES)'}")
    for v in bad:
        print("    FALHA:", v)
    failures += len(bad)

    # 2) o programa recusa todos os grupos que não podem ser encerrados?
    refused = wrongly_open = 0
    for g in groups:
        if g.can_close:
            continue
        plan = prepare(g, own=own, me=me)
        if plan.blocked:
            refused += 1
        else:
            wrongly_open += 1
            print(f"    FALHA: '{g.name}' ({g.category.value}) NÃO foi recusado!")
    not_closable = sum(1 for g in groups if not g.can_close)
    print(f"[2] Grupos protegidos/desconhecidos/mistos recusados: {refused} de {not_closable}"
          f"  {'OK' if not wrongly_open else 'FALHA'}")
    failures += wrongly_open

    # 3) simulação de erro do classificador: marca os PROTEGIDOS como encerráveis e vê se as travas independentes seguram
    leaks = []
    protected = [g for g in groups if g.category == Category.PROTEGIDO]
    for g in protected:
        forced = dataclasses.replace(g, can_close=True, category=Category.SEGURO)
        plan = prepare(forced, own=own, me=me)
        if not plan.blocked or plan.targets:          # só é "vazamento" se sobrou algo para encerrar
            leaks.append((g, plan.blocked))
    print(f"[3] Simulando um erro do classificador em {len(protected)} grupos PROTEGIDOS: "
          f"{len(protected) - len(leaks)} recusados pelas travas independentes")
    if leaks:
        print("    ATENÇÃO: estes só seriam protegidos pelo classificador (sem trava extra):")
        print("    " + ", ".join(sorted({g.name for g, _ in leaks})[:30]))
    # falha de verdade: processos do Windows, do emulador ou de outro dono que escaparam
    critical = [g.name for g, _ in leaks
                if any(t in g.tags for t in ("windows", "emulator", "system", "self", "security"))]
    if critical:
        print("    FALHA CRÍTICA: escaparam das travas:", ", ".join(critical))
        failures += len(critical)

    # 4) lista para revisão humana
    closable = [g for g in groups if g.can_close]
    print(f"\n[4] O programa deixaria você encerrar {len(closable)} aplicativos. REVISE A LISTA:")
    print(f"{'Categoria':<10} {'Aplicativo':<30} {'Proc':>4} {'RAM(MB)':>8}  Assinado por / Empresa")
    print("-" * 110)
    for g in sorted(closable, key=lambda x: x.ram_mb, reverse=True):
        rep = g.members[0]
        c = cls[rep.pid]
        who = f"{c.signer or '-'} / {rep.meta.company or '-'}"
        print(f"{g.category.value:<10} {g.name[:30]:<30} {len(g.members):>4} {g.ram_mb:>8.0f}  {who[:60]}")

    print("\n" + ("RESULTADO: TUDO CERTO. Nenhuma regra de proteção foi quebrada." if failures == 0
                   else f"RESULTADO: {failures} PROBLEMA(S) ENCONTRADO(S). Copie esta tela e envie."))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())