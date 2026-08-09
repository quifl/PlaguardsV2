"""PlagWeb - the Flask dashboard. Thin web layer over the shared
GuardModules pipeline."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, flash, g, jsonify, redirect, render_template, request, url_for

from ..GuardModules import PlagBatch, PlagConfig, PlagEngine, PlagFilter, PlagGrep, PlagIntel, PlagReport
from ..GuardModules import PlagGeo, PlagLinks, PlagStore, PlagTable

VALID_STATUSES = {"confirmed_threat", "false_positive", "unreviewed", "unknown"}


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    app.config["DB_PATH"] = db_path

    @app.template_filter("timestamp_to_str")
    def timestamp_to_str(ts: int) -> str:
        from datetime import timedelta, timezone
        offset = PlagConfig.get_utc_offset(get_db())
        moment = datetime.fromtimestamp(ts, tz=timezone.utc) + timedelta(hours=offset)
        return moment.strftime("%Y-%m-%d %H:%M")

    def get_db():
        if "db" not in g:
            g.db = PlagStore.get_conn(app.config["DB_PATH"])
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.context_processor
    def inject_latest_analysis():
        """The guided tour needs somewhere to point when it reaches the
        results-page steps."""
        try:
            rows = PlagStore.list_analyses(get_db(), limit=1)
        except Exception:
            rows = []
        return {
            "latest_analysis_id": rows[0]["id"] if rows else None,
            "batch_limits": PlagBatch.limits(),
            "lookup_types": PlagGrep.LOOKUP_TYPES,
        }

    @app.route("/")
    def index():
        return render_template("index.html", lookup=None)

    @app.route("/analyze", methods=["POST"])
    def do_analyze():
        uploads = [f for f in request.files.getlist("file") if f and f.filename]
        skip_intel = request.form.get("skip_intel") == "on"
        conn = get_db()

        if uploads:
            try:
                batch, skipped = PlagBatch.collect(uploads)
            except PlagBatch.BatchError as exc:
                flash(str(exc), "error")
                return redirect(url_for("index"))

            if not batch:
                detail = f" Skipped: {', '.join(skipped)}." if skipped else ""
                flash("Nothing analysable in that upload." + detail, "error")
                return redirect(url_for("index"))

            created = [
                PlagEngine.run_analysis(
                    text, filename=name, skip_intel=skip_intel, conn=conn,
                    source_kind="file",
                )["id"]
                for name, text in batch
            ]

            if skipped:
                flash(f"Skipped {len(skipped)}: {', '.join(skipped[:6])}"
                      + (" …" if len(skipped) > 6 else ""), "error")

            if len(created) == 1:
                return redirect(url_for("view_analysis", analysis_id=created[0]))

            limit = PlagConfig.get_history_limit(conn)
            note = ""
            if len(created) > limit:
                note = (f" Only the {limit} most recent are kept - raise the history "
                        f"limit in Settings if you need more.")
            flash(f"Analyzed {len(created)} files.{note}", "success")

            # A batch can go straight to one merged PDF instead of the list.
            if request.form.get("batch_report") == "combined":
                return redirect(url_for("batch_report_view",
                                        ids=",".join(str(i) for i in created)))
            return redirect(url_for("history", selected=",".join(str(i) for i in created)))

        text = request.form.get("script_text", "")
        if not text.strip():
            flash("Paste a script or choose a file first.", "error")
            return redirect(url_for("index"))

        result = PlagEngine.run_analysis(
            text, filename="pasted-script", skip_intel=skip_intel, conn=conn,
            source_kind="pasted",
        )
        return redirect(url_for("view_analysis", analysis_id=result["id"]))

    @app.route("/example")
    def run_example():
        """Analyze the bundled demo script so a new user can see a full
        result and report without having to find a sample first."""
        sample = Path(__file__).resolve().parents[2] / "samples" / "example-analysis.ps1"
        if not sample.exists():
            flash("The bundled example script is missing from samples/.", "error")
            return redirect(url_for("index"))

        conn = get_db()
        result = PlagEngine.run_analysis(
            sample.read_text(encoding="utf-8", errors="replace"),
            filename="example-analysis.ps1",
            # The IOC check is part of an analysis, so the demo runs it too;
            # ?intel=0 opts out for an offline walkthrough.
            skip_intel=request.args.get("intel", "1") == "0",
            conn=conn,
            source_kind="file",
        )
        flash("Loaded the bundled example analysis.", "success")
        return redirect(url_for("view_analysis", analysis_id=result["id"]))

    @app.route("/lookup", methods=["POST"])
    def do_lookup():
        value = request.form.get("ioc_value", "").strip()
        if not value:
            flash("Enter a value to look up.", "error")
            return redirect(url_for("index"))

        requested = request.form.get("ioc_type", "auto")
        ioc_type, note = PlagGrep.resolve_lookup_type(value, requested)
        if ioc_type is None:
            lookup = {"value": value, "type": None, "requested": requested,
                      "note": note, "results": []}
        else:
            refanged = PlagGrep.refang(value)
            finding = PlagGrep.Finding(type=ioc_type, value=refanged)
            conn = get_db()
            PlagIntel.enrich([finding], conn=conn, use_cache=True)
            results = [
                {
                    "label": PlagConfig.get_provider_label(source),
                    "url": PlagLinks.reference_url(source, ioc_type, refanged),
                    **r,
                }
                for source, r in finding.intel.items() if r.get("verdict") != "not_checked"
            ]
            lookup = {"value": refanged, "type": ioc_type, "requested": requested,
                      "note": note, "results": results}
        return render_template("index.html", lookup=lookup)

    @app.route("/analysis/<int:analysis_id>")
    def view_analysis(analysis_id):
        conn = get_db()
        data = PlagStore.get_analysis(conn, analysis_id)
        if data is None:
            return render_template("404.html"), 404
        # Same rows as the report, so the dashboard and the PDF never differ.
        resolved_display = [
            PlagReport._resolved_row(name, value)
            for name, value in (data.get("resolved_vars") or {}).items()
        ]
        intel_labels = {p["id"]: p["label"] for p in PlagConfig.PROVIDERS}
        intel_labels["scope"] = "Scope check"
        # Reuse the report's summarising so the dashboard headline and the
        # PDF never disagree about a finding's verdict.
        for finding in data["findings"]:
            intel = finding.get("intel") or {}
            scope = intel.get("scope")
            finding["scope_note"] = scope.get("detail", "") if scope else ""
            finding["intel_display"] = [
                {
                    "label": intel_labels.get(source, source),
                    # Follow-through to the provider's own detail page.
                    "url": PlagLinks.reference_url(
                        source, finding.get("type"), finding.get("value") or ""
                    ),
                    **result,
                }
                for source, result in sorted(intel.items())
                if source != "scope" and result.get("verdict") != "not_checked"
            ]
            finding["intel_summary"] = PlagReport._summarise_intel(finding["intel_display"], scope)
        return render_template(
            "result.html", analysis=data,
            resolved_display=resolved_display, intel_labels=intel_labels,
        )

    @app.route("/analysis/<int:analysis_id>/finding/<int:finding_id>/triage", methods=["POST"])
    def triage_finding(analysis_id, finding_id):
        payload = request.get_json(silent=True) or request.form
        status = payload.get("status")
        note = payload.get("note", "")
        if status not in VALID_STATUSES:
            return jsonify({"error": "invalid status"}), 400
        conn = get_db()
        PlagStore.update_triage(conn, finding_id, status, note)
        return jsonify({"ok": True, "status": status})

    @app.route("/analysis/<int:analysis_id>/triage-all", methods=["POST"])
    def triage_all(analysis_id):
        """Apply one verdict to every finding in the analysis at once."""
        payload = request.get_json(silent=True) or request.form
        status = payload.get("status")
        if status not in VALID_STATUSES:
            return jsonify({"error": "invalid status"}), 400
        conn = get_db()
        data = PlagStore.get_analysis(conn, analysis_id)
        if data is None:
            return jsonify({"error": "not found"}), 404
        for finding in data["findings"]:
            PlagStore.update_triage(conn, finding["id"], status, finding.get("triage_note") or "")
        return jsonify({"ok": True, "status": status, "updated": len(data["findings"])})

    def _render_report_response(analysis_id: int, disposition: str):
        conn = get_db()
        data = PlagStore.get_analysis(conn, analysis_id)
        if data is None:
            return render_template("404.html"), 404
        # ?redact=1 prints indicator values black-on-black.
        redact_iocs = request.args.get("redact", "0") == "1"
        analyst_name = PlagConfig.get_analyst_name(conn)
        pdf_bytes = PlagReport.render_pdf(
            data,
            analyst_name=analyst_name,
            utc_offset=PlagConfig.get_utc_offset(conn),
            redact_iocs=redact_iocs,
        )
        suffix = "-redacted" if redact_iocs else ""
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'{disposition}; filename="plaguardsv2-report-{analysis_id}{suffix}.pdf"'
            },
        )

    @app.route("/analysis/<int:analysis_id>/report/view")
    def view_report(analysis_id):
        """A wrapper page around the PDF.

        Serving the PDF straight from this URL leaves the browser to name the
        tab after the last path segment ("view") with its own generic icon;
        an HTML shell gets the report a real title and the Plaguards mark."""
        return render_template(
            "report_view.html",
            report_title=f"Plaguards Report {analysis_id}",
            pdf_url=url_for("inline_report", analysis_id=analysis_id,
                            **request.args.to_dict()),
        )

    @app.route("/analysis/<int:analysis_id>/report/pdf")
    def inline_report(analysis_id):
        return _render_report_response(analysis_id, "inline")

    @app.route("/analysis/<int:analysis_id>/report/download")
    def download_report(analysis_id):
        return _render_report_response(analysis_id, "attachment")

    @app.route("/analysis/<int:analysis_id>/table.<fmt>")
    def download_table(analysis_id, fmt):
        """Findings as a spreadsheet - the same data as the PDF, but sortable.

        Geolocation columns are filled in live, so an analysis run before a
        GeoIP source was configured still exports enriched rows.
        """
        if fmt not in ("csv", "xlsx"):
            return render_template("404.html"), 404

        conn = get_db()
        data = PlagStore.get_analysis(conn, analysis_id)
        if data is None:
            return render_template("404.html"), 404

        geo = {}
        for finding in data["findings"]:
            if finding.get("type") not in ("ip", "ip_port"):
                continue
            host = str(finding.get("value", "")).rsplit(":", 1)[0] \
                if finding.get("type") == "ip_port" else str(finding.get("value", ""))
            if host and host not in geo:
                geo[host] = PlagGeo.locate(host, conn)

        rows = PlagTable.build_rows(data, geo)
        stem = f"plaguardsv2-findings-{analysis_id}"
        if fmt == "csv":
            payload, mimetype = PlagTable.to_csv(rows), "text/csv; charset=utf-8"
        else:
            if not PlagTable.xlsx_available():
                flash("Excel export needs openpyxl - install it, or use CSV.", "error")
                return redirect(url_for("view_analysis", analysis_id=analysis_id))
            payload = PlagTable.to_xlsx(rows, title=f"Analysis {analysis_id}")
            mimetype = ("application/vnd.openxmlformats-officedocument"
                        ".spreadsheetml.sheet")
        return Response(payload, mimetype=mimetype, headers={
            "Content-Disposition": f'attachment; filename="{stem}.{fmt}"'
        })

    @app.route("/history")
    def history():
        conn = get_db()
        rows = PlagStore.list_analyses(conn)
        # After a batch run, the analyses that were just created come back
        # pre-ticked so the export/delete buttons act on exactly that batch.
        selected = {
            int(i) for i in (request.args.get("selected") or "").split(",") if i.isdigit()
        }
        return render_template(
            "history.html", analyses=rows, selected=selected,
            history_limit=PlagConfig.get_history_limit(conn),
        )

    @app.route("/history/report/view")
    def batch_report_view():
        """Wrapper page for the combined report - see view_report."""
        ids = [i for i in (request.args.get("ids") or "").split(",") if i.isdigit()]
        label = ", ".join(ids[:4]) + (" +" if len(ids) > 4 else "")
        return render_template(
            "report_view.html",
            report_title=f"Plaguards Report {label}" if ids else "Plaguards Report",
            pdf_url=url_for("batch_report", **request.args.to_dict()),
        )

    @app.route("/history/report")
    def batch_report():
        """One combined PDF for a list of ids, reachable by GET so a batch run
        can redirect straight to it."""
        conn = get_db()
        ids = [int(i) for i in (request.args.get("ids") or "").split(",") if i.isdigit()]
        analyses = [a for a in (PlagStore.get_analysis(conn, i) for i in ids) if a]
        if not analyses:
            flash("Nothing to report on.", "error")
            return redirect(url_for("history"))
        pdf_bytes = PlagReport.render_combined_pdf(
            analyses,
            analyst_name=PlagConfig.get_analyst_name(conn),
            utc_offset=PlagConfig.get_utc_offset(conn),
            redact_iocs=request.args.get("redact") == "1",
        )
        return Response(
            pdf_bytes, mimetype="application/pdf",
            headers={"Content-Disposition":
                     'inline; filename="plaguardsv2-combined-report.pdf"'},
        )

    @app.route("/history/bulk-delete", methods=["POST"])
    def bulk_delete():
        ids = [int(i) for i in request.form.getlist("analysis_id")]
        conn = get_db()
        removed = PlagStore.delete_analyses(conn, ids)
        flash(f"Deleted {removed} analysis(es).", "success")
        return redirect(url_for("history"))

    @app.route("/history/bulk-export", methods=["POST"])
    def bulk_export():
        import io
        import zipfile

        ids = [int(i) for i in request.form.getlist("analysis_id")]
        redact_iocs = request.form.get("redact", "0") == "1"
        conn = get_db()
        analyst_name = PlagConfig.get_analyst_name(conn)
        utc_offset = PlagConfig.get_utc_offset(conn)

        # One document covering everything selected, rather than a zip of
        # separate PDFs.
        if request.form.get("combined") == "1":
            analyses = [a for a in (PlagStore.get_analysis(conn, i) for i in ids) if a]
            if not analyses:
                flash("Select at least one analysis to export.", "error")
                return redirect(url_for("history"))
            pdf_bytes = PlagReport.render_combined_pdf(
                analyses, analyst_name=analyst_name, utc_offset=utc_offset,
                redact_iocs=redact_iocs,
            )
            return Response(
                pdf_bytes,
                mimetype="application/pdf",
                headers={"Content-Disposition":
                         'attachment; filename="plaguardsv2-combined-report.pdf"'},
            )

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for analysis_id in ids:
                data = PlagStore.get_analysis(conn, analysis_id)
                if data is None:
                    continue
                pdf_bytes = PlagReport.render_pdf(
                    data, analyst_name=analyst_name, utc_offset=utc_offset,
                    redact_iocs=redact_iocs,
                )
                zf.writestr(f"plaguardsv2-report-{analysis_id}.pdf", pdf_bytes)
        buf.seek(0)
        return Response(
            buf.getvalue(),
            mimetype="application/zip",
            headers={"Content-Disposition": 'attachment; filename="plaguardsv2-reports.zip"'},
        )

    @app.route("/tutorial")
    def tutorial():
        return render_template("tutorial.html")

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        conn = get_db()
        if request.method == "POST":
            form_type = request.form.get("form", "keys")
            if form_type == "general":
                limit = request.form.get("history_limit", "").strip()
                if limit.isdigit():
                    PlagConfig.set_history_limit(conn, int(limit))
                PlagConfig.set_analyst_name(conn, request.form.get("analyst_name", ""))
                PlagConfig.set_geoip_db_path(conn, request.form.get("geoip_db", ""))
                offset = request.form.get("utc_offset", "").strip()
                if offset:
                    try:
                        PlagConfig.set_utc_offset(conn, float(offset))
                    except ValueError:
                        flash("UTC offset must be a number between -12 and +14.", "error")
                flash("General settings saved.", "success")
            elif form_type == "clear_history":
                PlagStore.delete_all_analyses(conn)
                flash("All analysis history cleared.", "success")
            else:
                for provider in PlagConfig.PROVIDERS:
                    value = request.form.get(provider["id"], "").strip()
                    if value:
                        PlagConfig.set_api_key(conn, provider["id"], value)
                flash("API keys saved.", "success")
            return redirect(url_for("settings"))

        current_keys = PlagConfig.all_keys(conn)
        return render_template(
            "settings.html",
            providers=PlagConfig.PROVIDERS,
            current_keys=current_keys,
            history_limit=PlagConfig.get_history_limit(conn),
            analyst_name=PlagConfig.get_analyst_name(conn),
            utc_offset=PlagConfig.get_utc_offset(conn),
            geoip_db=PlagConfig.get_geoip_db_path(conn),
        )

    return app
