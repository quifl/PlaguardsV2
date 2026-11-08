"""Command-line interface for fast, scriptable IR triage."""
from __future__ import annotations

import dataclasses
import json
import os
import sys

import click

from .GuardModules import PlagConfig, PlagEncode, PlagEngine, PlagReport, PlagStore

SEVERITY_COLOR = {"high": "red", "medium": "yellow", "low": "green", "info": "white"}
VERDICT_COLOR = {
    "malicious": "red", "suspicious": "yellow", "clean": "green",
    "unknown": "white", "not_checked": "bright_black", "error": "bright_black",
}


@click.group()
def cli():
    """PlaguardsV2: static deobfuscation and IOC triage for PowerShell, VBScript, JScript and batch scripts."""


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
@click.option("--pipeline", type=click.Choice(PlagEngine.PIPELINES), default=None,
              help=f"Deobfuscation pipeline (default: {PlagEngine.DEFAULT_PIPELINE}).")
@click.option("--legacy-pipeline", is_flag=True, help="Same as --pipeline legacy: the single-text engine.")
@click.option("--max-depth", type=click.IntRange(0, 64), default=None,
              help="Deepest layer the layered pipeline opens (default: 12).")
@click.option("--emulation", is_flag=True, help="Opt-in emulation of extracted functions (not available yet).")
@click.option("--explain", is_flag=True, help="Print the layer tree and the provenance JSON.")
def analyze(path, no_intel, no_cache, no_store, triage, pdf_path, json_path, redact_iocs, db_path,
            pipeline, legacy_pipeline, max_depth, emulation, explain):
    """Analyze PATH, or stdin when PATH is omitted or '-'. Provider keys come
    from the dashboard's Settings page, or from .env."""
    if emulation:
        raise click.UsageError("--emulation is not available in this version; nothing was run.")
    if legacy_pipeline:
        if pipeline not in (None, "legacy"):
            raise click.UsageError("--legacy-pipeline contradicts --pipeline " + pipeline)
        pipeline = "legacy"
    pipeline = pipeline or PlagEngine.DEFAULT_PIPELINE
    if (max_depth is not None or explain) and pipeline != "layered":
        raise click.UsageError("--max-depth and --explain need the layered pipeline")

    if path and path != "-":
        with open(path, "rb") as fh:
            text = PlagEncode.decode_script(fh.read())
        # The name only: a full path would put the analyst's folder layout on the report cover.
        filename = os.path.basename(path)
    else:
        # Bytes, decoded like a file: `analyze - < script.ps1` may well be UTF-16.
        stream = getattr(sys.stdin, "buffer", None)
        text = PlagEncode.decode_script(stream.read()) if stream is not None else sys.stdin.read()
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
        pipeline=pipeline,
        max_depth=max_depth,
    )

    _print_summary(result)
    if explain and result.get("layers"):
        _print_explain(result["layers"])

    # The stored copy carries triage verdicts; the in-memory result never does.
    stored = PlagStore.get_analysis(conn, result["id"]) if conn is not None and result.get("id") else None
    if triage:
        _interactive_triage(conn, result)
        if conn is not None and result.get("id"):
            stored = PlagStore.get_analysis(conn, result["id"])

    if json_path:
        payload = _json_safe(result)
        if stored:
            # Matched by indicator, since the database returns findings sorted by severity.
            verdicts = {(f["type"], f["value"]): f.get("triage_status") for f in stored["findings"]}
            for finding in payload["findings"]:
                finding["triage_status"] = verdicts.get((finding["type"], finding["value"]), "unreviewed")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        click.echo(f"\nJSON written to {json_path}")

    if pdf_path:
        analyst_name = PlagConfig.get_analyst_name(conn)
        pdf_bytes = PlagReport.render_pdf(
            stored or result, analyst_name=analyst_name, utc_offset=PlagConfig.get_utc_offset(conn),
            redact_iocs=redact_iocs, conn=conn,
        )
        with open(pdf_path, "wb") as fh:
            fh.write(pdf_bytes)
        click.echo(f"PDF report written to {pdf_path}")

    if conn is not None:
        conn.close()


@cli.command(name="list")
@click.option("--db-path", type=click.Path(dir_okay=False), default=None, help="SQLite DB path (default: data/plaguardsv2.db).")
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
            "No further static rewrites could be safely applied. The findings below list "
            "obfuscation techniques that were detected but not fully resolved."
        )
    else:
        click.echo("No deobfuscation transforms were needed; the input already appears to be plaintext.")

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


def _print_explain(layers: dict) -> None:
    """The layer tree, then the full provenance JSON."""
    click.echo(click.style("\n--- Layer tree ---", bold=True))
    children: dict = {}
    for art in layers["artifacts"]:
        children.setdefault(art["parent_id"], []).append(art)

    def walk(parent_id, indent):
        for art in children.get(parent_id, []):
            how = f" via {art['edge']}: {art['edge_detail']}" if art["edge"] else ""
            flags = f" [{', '.join(art['flags'])}]" if art["flags"] else ""
            click.echo(f"{'  ' * indent}layer {art['id']} {art['language']} "
                       f"({art['size']} bytes, {art['rounds']} round(s)){how}{flags}")
            walk(art["id"], indent + 1)

    walk(None, 0)
    for key in ("limits_hit", "needs_review", "rejected", "notes"):
        if layers.get(key):
            click.echo(f"{key}: {len(layers[key])}")
    click.echo(click.style("\n--- Provenance (canonical JSON) ---", bold=True))
    click.echo(json.dumps(layers, indent=2, default=str))


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
