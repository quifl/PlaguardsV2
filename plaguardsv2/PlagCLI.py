"""Command-line interface for fast, scriptable IR triage."""
from __future__ import annotations

import dataclasses
import json
import sys

import click

from .GuardModules import PlagConfig, PlagEngine, PlagStore, PlagReport

SEVERITY_COLOR = {"high": "red", "medium": "yellow", "low": "green", "info": "white"}
VERDICT_COLOR = {
    "malicious": "red", "suspicious": "yellow", "clean": "green",
    "unknown": "white", "not_checked": "bright_black", "error": "bright_black",
}


@click.group()
def cli():
    """PlaguardsV2: fast static triage for obfuscated PowerShell / suspicious scripts."""


@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, allow_dash=True), required=False)
@click.option("--no-intel", is_flag=True, help="Skip all threat-intel provider lookups.")
@click.option("--no-cache", is_flag=True, help="Bypass the local threat-intel cache.")
@click.option("--no-store", is_flag=True, help="Don't persist this analysis to the local database.")
@click.option("--triage", is_flag=True, help="Interactively mark each finding as threat/false-positive.")
@click.option("--pdf", "pdf_path", type=click.Path(dir_okay=False), default=None, help="Write a PDF report to this path.")
@click.option("--json", "json_path", type=click.Path(dir_okay=False), default=None, help="Write JSON results to this path.")
@click.option("--redact-iocs", is_flag=True, help="Print indicator values black-on-black in the PDF (redacted copy).")
@click.option("--db-path", type=click.Path(dir_okay=False), default=None, help="SQLite DB path (default: data/plaguardsv2.db).")
def analyze(path, no_intel, no_cache, no_store, triage, pdf_path, json_path, redact_iocs, db_path):
    """Analyze PATH (or stdin if omitted / '-'). Provider keys are read from
    the Settings database / environment - see PlagConfig.py / .env."""
    if path and path != "-":
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        filename = path
    else:
        text = sys.stdin.read()
        filename = "stdin"

    conn = None
    if not no_store:
        conn = PlagStore.get_conn(db_path)

    result = PlagEngine.run_analysis(
        text,
        filename=filename,
        skip_intel=no_intel,
        conn=conn,
        use_cache=not no_cache,
    )

    _print_summary(result)

    if triage:
        _interactive_triage(conn, result)

    if json_path:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(_json_safe(result), fh, indent=2, default=str)
        click.echo(f"\nJSON written to {json_path}")

    if pdf_path:
        analyst_name = PlagConfig.get_analyst_name(conn)
        pdf_bytes = PlagReport.render_pdf(
            result, analyst_name=analyst_name, utc_offset=PlagConfig.get_utc_offset(conn),
            redact_iocs=redact_iocs
        )
        with open(pdf_path, "wb") as fh:
            fh.write(pdf_bytes)
        click.echo(f"PDF report written to {pdf_path}")

    if conn is not None:
        conn.close()


@cli.command(name="list")
@click.option("--db-path", type=click.Path(dir_okay=False), default=None)
@click.option("--limit", default=25, show_default=True)
def list_analyses(db_path, limit):
    """List past analyses stored in the local database."""
    conn = PlagStore.get_conn(db_path)
    rows = PlagStore.list_analyses(conn, limit=limit)
    conn.close()
    if not rows:
        click.echo("No analyses stored yet.")
        return
    for r in rows:
        click.echo(f"#{r['id']:<4} {r['filename']:<30} findings={r['finding_count']:<3} high={r['high_count'] or 0}")


def _print_summary(result: dict) -> None:
    click.echo(click.style(f"\n== {result['filename']} ==", bold=True))
    if result["pass_log"]:
        click.echo(click.style(f"Deobfuscation applied {len(result['pass_log'])} transform(s):", bold=True))
        for entry in result["pass_log"]:
            click.echo(f"  - {entry}")
    elif result["findings"]:
        click.echo(
            "No further static rewrites could be safely applied - see findings below for "
            "obfuscation techniques that were detected but couldn't be fully resolved automatically."
        )
    else:
        click.echo("No deobfuscation transforms were needed - input appears to already be plaintext.")

    click.echo(click.style("\n--- Deobfuscated script ---", bold=True))
    click.echo(result["deobfuscated"])

    resolved = result.get("resolved_vars") or {}
    if resolved:
        click.echo(click.style(f"\n--- {len(resolved)} statically resolved variable(s) ---", bold=True))
        for name, value in resolved.items():
            click.echo(f"  ${name} = {value}")

    findings = result["findings"]
    click.echo(click.style(f"\n--- {len(findings)} finding(s) ---", bold=True))
    for f in findings:
        sev_color = SEVERITY_COLOR.get(f.severity, "white")
        mitre = ",".join(f.mitre) if f.mitre else "-"
        intel_bits = []
        for source, r in f.intel.items():
            if r.get("verdict") == "not_checked":
                continue
            color = VERDICT_COLOR.get(r.get("verdict"), "white")
            intel_bits.append(f"{source}={click.style(r.get('verdict'), fg=color)}")
        intel_str = " ".join(intel_bits) if intel_bits else "intel=not_checked"
        click.echo(
            f"[{click.style(f.severity.upper(), fg=sev_color)}] "
            f"{f.type:<11} {f.value[:60]:<60} mitre={mitre} {intel_str}"
        )


def _interactive_triage(conn, result: dict) -> None:
    if conn is None:
        click.echo("\n--triage requires storage; re-run without --no-store.", err=True)
        return
    analysis_id = result["id"]
    stored = PlagStore.get_analysis(conn, analysis_id)
    click.echo(click.style("\n--- Interactive triage ---", bold=True))
    for f in stored["findings"]:
        click.echo(f"\n{f['type']} : {f['value']}")
        click.echo(f"  context: {f['context']}")
        choice = click.prompt(
            "  Mark as [t]hreat / [f]alse-positive / [u]nknown / [s]kip",
            type=click.Choice(["t", "f", "u", "s"], case_sensitive=False),
            default="s",
        )
        status_map = {"t": "confirmed_threat", "f": "false_positive", "u": "unknown"}
        if choice.lower() in status_map:
            PlagStore.update_triage(conn, f["id"], status_map[choice.lower()])


def _json_safe(result: dict) -> dict:
    out = dict(result)
    out["findings"] = [
        dataclasses.asdict(f) if dataclasses.is_dataclass(f) else f
        for f in result["findings"]
    ]
    return out


if __name__ == "__main__":
    cli()
