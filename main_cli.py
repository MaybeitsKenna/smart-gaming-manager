"""Teste das Etapas 2 e 3: escaneia, verifica assinaturas, classifica e mostra o resultado.
SOMENTE LEITURA. Não encerra nada.

Uso:
    python main_cli.py                      -> resumo + 40 grupos que mais usam RAM
    python main_cli.py --cat SEGURO         -> só os classificados como SEGURO
    python main_cli.py --cat DESCONHECIDO   -> só os DESCONHECIDOS
    python main_cli.py --limit 100          -> mostra mais linhas
"""
import argparse
from collections import defaultdict

from sgm.scanner import scan_system
from sgm import signature
from sgm.signature import verify_signatures
from sgm.startup import read_startup_paths
from sgm.classifier import classify_all, Category
from sgm.knowledge import build_groups, format_card

CAT_BY_ARG = {"SEGURO": Category.SEGURO, "ATENCAO": Category.ATENCAO,
              "PROTEGIDO": Category.PROTEGIDO, "DESCONHECIDO": Category.DESCONHECIDO}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cat", choices=list(CAT_BY_ARG))
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--explain", help="mostra a explicação em linguagem simples dos aplicativos cujo nome contém este texto")
    ap.add_argument("--detail", help="mostra todas as evidências dos processos cujo nome contém este texto")
    args = ap.parse_args()

    print("1/3 Escaneando processos (cerca de 1 segundo)...")
    snap = scan_system()
    print("2/3 Verificando assinaturas digitais (pode levar de 5 a 30 segundos)...")
    sigs = verify_signatures({p.exe_path for p in snap.processes if p.exe_path})
    print(f"    assinaturas verificadas: {len(sigs)}")
    if not sigs:
        print(f"    !!! A verificação falhou. Motivo: {signature.LAST_ERROR or '(sem detalhe)'}")
    startup = read_startup_paths()
    print("3/3 Classificando...\n")
    cls = classify_all(snap.processes, sigs, startup)

    if args.detail:
        found = [p for p in snap.processes if args.detail.lower() in p.name.lower()][:3]
        if not found:
            print(f"Nenhum processo com '{args.detail}' no nome.")
        for p in found:
            c = cls[p.pid]
            print(f"--- {p.name} (PID {p.pid}) ---")
            print(f"Categoria : {c.category.value}\nMotivo    : {c.reason}")
            print(f"Caminho   : {p.exe_path}\nEmpresa   : {p.meta.company}\nProduto   : {p.meta.product}")
            print(f"Descrição : {p.meta.description}\nVersão    : {p.meta.version}")
            print(f"Assinatura: {c.sig_status} | {c.signer}\nPai       : {p.parent_name} (PID {p.parent_pid})")
            print(f"Inicia com o Windows: {'sim' if c.autostart else 'não detectado'}")
            for e in c.evidence:
                print(f"  - {e}")
            print()
        return

    if args.explain:
        groups = [g for g in build_groups(snap.processes, cls) if args.explain.lower() in g.name.lower()][:5]
        if not groups:
            print(f"Nenhum aplicativo com '{args.explain}' no nome.")
        for g in groups:
            print(format_card(g))
            print()
        return

    print(f"CPU total: {snap.cpu_total_percent:.1f}% | RAM: {snap.ram_used_mb:.0f}/{snap.ram_total_mb:.0f} MB "
          f"| Processos: {snap.process_count}")
    print("\nResumo por categoria:")
    for cat in Category:
        procs = [p for p in snap.processes if cls[p.pid].category == cat]
        print(f"  {cat.value:<13} {len(procs):>4} processos  {sum(p.ram_mb for p in procs):>8.0f} MB")
    closable = sum(1 for p in snap.processes if cls[p.pid].category in (Category.SEGURO, Category.ATENCAO))
    print(f"  Potencialmente encerráveis (SEGURO + ATENÇÃO): {closable}")

    suspects = [p for p in snap.processes if "suspect" in cls[p.pid].tags]
    if suspects:
        print("\n!!! PROCESSOS SUSPEITOS !!!")
        for p in suspects:
            print(f"  {p.name} (PID {p.pid}): {cls[p.pid].reason}\n    {p.exe_path}")

    groups = defaultdict(lambda: {"n": 0, "ram": 0.0, "cpu": 0.0, "c": None})
    for p in snap.processes:
        c = cls[p.pid]
        g = groups[(p.name.lower(), c.category)]
        g["n"] += 1; g["ram"] += p.ram_mb; g["cpu"] += p.cpu_percent
        g["c"] = g["c"] or c
        g["name"] = p.name
    rows = [g for (n, cat), g in groups.items() if not args.cat or cat == CAT_BY_ARG[args.cat]]
    rows.sort(key=lambda g: g["ram"], reverse=True)

    print(f"\n{'Categoria':<13} {'Nome':<28} {'Qtd':>3} {'RAM(MB)':>8} {'CPU%':>5}  Auto  Motivo")
    print("-" * 130)
    for g in rows[:args.limit]:
        c = g["c"]
        print(f"{c.category.value:<13} {g['name'][:28]:<28} {g['n']:>3} {g['ram']:>8.0f} {g['cpu']:>5.1f}  "
              f"{'sim ' if c.autostart else '    '}  {c.reason[:70]}")


if __name__ == "__main__":
    main()