from __future__ import annotations
import sys
from pathlib import Path
import json

import typer
from rich import print as rprint
from rich.table import Table
from rich.console import Console

from parsers import parse_apache_combined
from models import Detection
from detectors.engine import detect_from_jsonl

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Security Log Analyzer CLI")

# .ingest
ingest_app = typer.Typer(add_completion=False, no_args_is_help=True, help="Ingest & parse logs")

@ingest_app.command("file", help="Reads an Apache log file (combined) and outputs normalized JSONL.")
def ingest_file(
    input_path: Path = typer.Argument(..., exists=True, readable=True, help="Raw log file (Apache combined)"),
    output: Path = typer.Option(None, "--out", "-o", help="Write JSONL to file (otherwise, to stdout)"),
):
    total = 0
    parsed = 0
    outfh = sys.stdout if output is None else open(output, "w", encoding="utf-8")
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            for line in f:
                total += 1
                rec = parse_apache_combined(line)
                if rec is None:
                    continue
                parsed += 1
                outfh.write(rec.model_dump_jsonl() + "\n")
    finally:
        if output is not None:
            outfh.close()
    rprint(f"[green]OK[/green] lines read: {total}, successful parses: {parsed}")

app.add_typer(ingest_app, name="ingest")

# .detect
detect_app = typer.Typer(add_completion=False, no_args_is_help=True, help="Detecting rules/anomalies on JSONL")

@detect_app.command("run", help="Run detection on a normalized JSONL (from 'ingest').")
def detect_run(
    input_jsonl: Path = typer.Argument(..., exists=True, readable=True, help="JSONL file with normalized records"),
    rules_path: Path = typer.Option(Path("rules/detection_rules.yaml"), "--rules", help="YAML file with rules"),
    output: Path = typer.Option(None, "--out", "-o", help="Write detections to JSONL (otherwise, to stdout)"),
    pretty: bool = typer.Option(True, "--pretty/--no-pretty", help="Display nice summary in console"),
):
    detections = detect_from_jsonl(str(input_jsonl), str(rules_path))
    outfh = sys.stdout if output is None else open(output, "w", encoding="utf-8")
    try:
        for det in detections:
            outfh.write(det.model_dump_jsonl() + "\n")
    finally:
        if output is not None:
            outfh.close()
    if pretty:
        table = Table(title=f"Detections: {len(detections)}", show_lines=False)
        table.add_column("#", justify="right")
        table.add_column("Rule ID")
        table.add_column("Severity")
        table.add_column("Src IP")
        table.add_column("Count", justify="right")
        table.add_column("Window UTC")
        table.add_column("Summary")
        for idx, det in enumerate(detections, start=1):
            window = f"{det.ts_first.isoformat()} → {det.ts_last.isoformat()}"
            table.add_row(str(idx), det.rule_id, det.severity, det.src_ip or "-", str(det.count), window, det.summary)
        Console().print(table)

app.add_typer(detect_app, name="detect")

# .alert
alert_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Alert routing for detections"
)

@alert_app.command("run", help="Route alerts from a detections JSONL file using a YAML config.")
def alert_run(
    detections: Path = typer.Argument(..., exists=True, readable=True, help="JSONL file produced by 'detect run --out'"),
    config: Path = typer.Option(Path("config/alerting.yaml"), "--config", help="Alerting YAML configuration"),
    state: Path = typer.Option(Path(".state/alerts_state.json"), "--state", help="State file for dedup/rate-limiting"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Do not send to external routes; print to console"),
):
    try:
        from alerts.engine import route_alerts
        total, sent, suppressed = route_alerts(str(detections), str(config), str(state), dry_run=dry_run)
        rprint(f"[green]Alerting complete[/green] total={total}, sent={sent}, suppressed={suppressed}")
    except Exception as e:
        rprint(f"[red]Alerting failed:[/red] {e}")
        raise typer.Exit(code=1)

app.add_typer(alert_app, name="alert")

# .respond
respond_app = typer.Typer(add_completion=False, no_args_is_help=True, help="Auto-responder playbooks")

@respond_app.command("run", help="Run auto-responder playbooks against detections JSONL.")
def respond_run(
    detections: Path = typer.Argument(..., exists=True, readable=True, help="JSONL file produced by 'detect run'"),
    config: Path = typer.Option(Path("config/responding.yaml"), "--config", help="Responder playbooks YAML"),
    alert_config: Path = typer.Option(Path("config/alerting.yaml"), "--alert-config", help="Alerting YAML (for notify routes)"),
    state: Path = typer.Option(Path(".state/respond_state.json"), "--state", help="Responder state file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print intended actions without executing them"),
):
    try:
        from responders.engine import run_responder
        total, executed, suppressed = run_responder(
            str(detections), str(config), str(alert_config), str(state), dry_run=dry_run
        )
        rprint(f"[green]Responder complete[/green] detections={total}, actions_executed={executed}, actions_suppressed={suppressed}")
    except Exception as e:
        rprint(f"[red]Responder failed:[/red] {e}")
        raise typer.Exit(code=1)

app.add_typer(respond_app, name="respond")


if __name__ == "__main__":
    app()
    

    
    
