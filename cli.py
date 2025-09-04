from __future__ import annotations
import sys
from pathlib import Path

import typer
from rich import print as rprint

from parsers import parse_apache_combined

# Aplicația principală (va conține subcomenzi)
app = typer.Typer(add_completion=False, no_args_is_help=True, help="Security Log Analyzer CLI")

# Sub-aplicație dedicată pentru 'ingest'
ingest_app = typer.Typer(add_completion=False, no_args_is_help=True, help="Ingest & parse loguri")

@ingest_app.command("file", help="Citește un fișier de log Apache (combined) și scoate JSONL normalizat.")
def ingest_file(
    file: Path = typer.Option(..., exists=True, readable=True, help="Calea către fișierul de log"),
):
    """
    Exemplu:
      python cli.py ingest file --file sample_logs/apache_access.log > out.jsonl
    """
    total = 0
    parsed = 0
    with file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total += 1
            rec = parse_apache_combined(line)
            if rec is None:
                continue
            parsed += 1
            sys.stdout.write(rec.model_dump_jsonl() + "\n")
    rprint(f"[green]OK[/green] Linii citite: {total}, parse reușite: {parsed}")

# Înregistrăm sub-aplicația sub numele 'ingest'
app.add_typer(ingest_app, name="ingest")

if __name__ == "__main__":
    app()
