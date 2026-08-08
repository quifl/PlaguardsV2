# PlaguardsV2: Static Deobfuscation and IOC Triage for Blue Teams.

<p align="center">
<img src="plaguardsv2/PlagWeb/static/assets/PlaguardsBanner.png" width="620" alt="PlaguardsV2">
</p>

---

<p align="center">
 <a href="#"><img src="https://img.shields.io/badge/Static_Deobfuscator-blue"></a>
 <a href="#"><img src="https://img.shields.io/badge/IOC_Checker-red"></a>
 <a href="#"><img src="https://img.shields.io/badge/Automated_Reporting-white"></a>
 <a href="#"><img src="https://img.shields.io/badge/7_Threat_Intel_Providers-c81e4a"></a>
 <a href="https://github.com/baycysec/plaguards"><img src="https://img.shields.io/badge/Built_on-Plaguards_v1-640D5F"></a>
</p>

<p align="justify">PlaguardsV2 takes an obfuscated script, turns it back into something a human can read, and pulls out the indicators hiding underneath it. It is a spiritual v2 of <a href="https://github.com/baycysec/plaguards">Plaguards</a>: same purpose, rebuilt as a local-first application with a command-line interface, a web dashboard, and a shareable PDF report at the end of every analysis.</p>

<p align="justify">Nothing you submit is ever executed. Every transform is a rewrite of literal values — there is no <code>eval</code>, no sandbox, and no PowerShell process — so a hostile script cannot do anything by being analyzed. Deobfuscation, indicator extraction, storage and report generation all run entirely offline; the only thing that ever leaves the machine is an extracted indicator value sent to a threat-intel provider you configured yourself.</p>

## Motivation

<p align="justify">Attackers rarely ship readable PowerShell. They split strings across concatenations, Base64-encode whole stages, build characters out of arithmetic and scatter backticks through cmdlet names — all so that a defender, and a signature, sees noise instead of a URL. Most tooling in this space <em>detects</em> that a script is obfuscated and stops there, which leaves the responder with the same wall of text they started with.</p>

<p align="justify">PlaguardsV2 exists to finish the job, and to do it for more than PowerShell: the same corpus of techniques shows up in the .vbs, .js, .bat and .cmd files that arrive alongside it, and in the log lines that record them after the fact. It ends with an artefact you can hand to somebody else — a report that records what was applied, what was found, and what the analyst decided.</p>

## Main Features

|No.|Feature|Summary|
|:-:|:------|:------|
|1.|**Static deobfuscation**|Multi-pass, multi-language, and never executing anything. **PowerShell:** `-EncodedCommand` blobs, `[Convert]::FromBase64String` literals (gzip/deflate stages inflated transparently), string concatenation, `-join` / `-split` / `-replace`, the `-f` format operator, `[char]` code points and arithmetic, `-bxor`, `$(...)` subexpressions, `[Text.Encoding]::*.GetString`, `[byte[]]` arrays, junk backticks, redundant `[string]` casts, and sequential variable tracking through reassignment chains. **VBScript:** `Chr()` concatenation, `StrReverse`, `Replace`, Base64 literals, literal variable propagation. **JScript:** `String.fromCharCode`, `atob`, `unescape` / `decodeURIComponent`, hex and unicode escapes, Base64 literals, `split`/`reverse`/`join` chains, `replace`, literal variable propagation. **Batch/cmd:** `set` chains, `%var%` and delayed `!var!` expansion, `%var:~offset,length%` carving, `%var:find=replace%`, caret escapes. Every pass that fires is recorded in a transform log.|
|2.|**Indicator & signature extraction**|IPs, domains, URLs, emails, MD5/SHA1/SHA256 hashes (including defanged forms like `1[.]2[.]3[.]4` and `hxxp://`), plus registry keys, mutexes, User-Agents, `ip:port` pairs and partial hashes. A signature ruleset covers download cradles, in-memory execution, LOLBins, persistence, AMSI references and hidden-window flags, each tagged with a MITRE ATT&CK technique.|
|3.|**Seven threat-intel providers**|VirusTotal, abuse.ch (MalwareBazaar / ThreatFox / URLhaus), AbuseIPDB, AlienVault OTX, Shodan, GreyNoise and Pulsedive behind one config point and one Settings page. All optional, all cached locally. Every result row links straight to that provider's own page for the indicator. Reserved and non-routable values are marked *not applicable* with the reason rather than burning quota on a lookup that cannot return anything.|
|3b.|**IOC Checker**|A single indicator, checked without running a full analysis. Leave the type on **Detect automatically** and the value's shape decides; or pick **IP**, **Domain**, **URL**, **File hash** or **Malware signature / family** explicitly. A signature (`AgentTesla`, `Formbook`) has no detectable shape, so choosing the type by hand is the only way to reach it — the same `hash` / `signature` / `domain` / `ip` query set the original Plaguards offered.|
|4.|**Analyst triage**|Mark each finding Confirmed Threat, False Positive or Unknown, individually or in bulk. Severity describes the *technique observed*, not confirmed impact — your verdict is what the report treats as the conclusion.|
|5.|**Automated PDF reporting**|A cover, a clickable table of contents quoting the page each section starts on, and a formal disclaimer notice — then page 1: the summary with charts, a findings table, per-finding detail grouped by severity, the transform log with resolved variables, and both scripts in full. Indicators are defanged throughout, and can optionally be redacted black-on-black before sharing. A batch can produce separate PDFs or one combined document that lists every analysis and its sections in the contents.|
|6.|**CLI and dashboard, one pipeline**|Both front ends call the same engine and share one database, so a script analyzed from a terminal appears in the dashboard's History, and a verdict recorded in the browser shows up in a report generated later from the command line.|

## Requirements

- Python 3.12+
- Docker and Docker Compose v2 *(optional — the installer falls back to a local virtualenv)*
- Port 8000

> [!NOTE]
> **No manual installation needed — one script handles everything.**

## Deployment and Usage

**1. Clone the repository.**

```console
git clone <your-fork-url> plaguardsv2
cd plaguardsv2
```

**2. Run the installer.**

```powershell
# Windows
.\install.ps1
```

```bash
# Linux / macOS
./install.sh
```

Either script creates `.env` from `.env.example` if it is missing, uses Docker when a daemon is actually running, otherwise sets up a local virtual environment — then starts the app and opens `http://localhost:8000`.

**3. Try it without finding a sample first.** The dashboard's *Run the example script* button analyzes the bundled inert demo in `samples/` end to end, report included.

### Threat intel setup (optional)

Configure any subset from the **Settings** page, or edit `.env` directly. Without a key a provider is skipped and labelled `not_checked`; deobfuscation and indicator extraction are unaffected.

| Provider | Env var | Get a key |
|---|---|---|
| VirusTotal | `VT_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| abuse.ch (MalwareBazaar / ThreatFox / URLhaus) | `ABUSECH_API_KEY` | https://auth.abuse.ch/ |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api |
| AlienVault OTX | `OTX_API_KEY` | https://otx.alienvault.com/api |
| Shodan | `SHODAN_API_KEY` | https://account.shodan.io/ |
| GreyNoise (Community) | `GREYNOISE_API_KEY` | https://viz.greynoise.io/account/ |
| Pulsedive | `PULSEDIVE_API_KEY` | https://pulsedive.com/api/ |

> [!WARNING]
> Keys are stored in the local SQLite database on the machine you run this on. Do not commit `.env`, and do not hardcode keys in source.

### Dashboard

| Page | What it does |
|---|---|
| **New Analysis** | Paste a script, or drop files anywhere on the page — `.ps1 .txt .vbs .js .bat .cmd .log`, or a `.zip`. Up to 200 files, 5 MB each, 100 MB per submission. A batch can produce separate reports or one combined document. The second card is the **IOC Checker**: one indicator, with the type detected automatically or chosen from the list. |
| **Result** | Deobfuscated script, transform log, resolved variables and the original input on the left; findings with context, MITRE mapping, threat intel and triage controls on the right. |
| **History** | Past analyses newest first. Select rows to export a zip of PDFs, build a combined report, or delete in bulk. Retention is configurable. |
| **Tutorial** | Every feature explained page by page, plus a guided tour that walks the whole app. |
| **Settings** | API keys, history retention, the analyst name printed on reports, the UTC offset used for timestamps, and a danger zone that clears stored history. |

### CLI usage

```console
python plaguardsv2-cli.py analyze <path|->     # a file, or '-'/omitted for stdin
    --pdf out.pdf                              # write a PDF report
    --json out.json                            # write JSON results
    --redact-iocs                              # print indicator values black-on-black
    --triage                                   # mark each finding interactively
    --no-intel                                 # skip all threat-intel providers
    --no-cache                                 # bypass the local intel cache
    --no-store                                 # don't persist to the local database
    --db-path FILE                             # use a different SQLite database

python plaguardsv2-cli.py list                 # show past analyses
```

### Manual setup

**Docker:**

```console
cp .env.example .env
docker compose up --build
```

**Local Python:**

```console
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
flask --app plaguardsv2.PlagWeb run --debug
```

**Tests:**

```console
pip install -r requirements-dev.txt
pytest
```

The suite includes a corpus of benign, inert samples covering every supported technique across all seven accepted file types — each one hides the same banner behind a different trick, and the tests assert we get the cleartext back.

## Architecture

```
plaguardsv2/
  GuardModules/
    PlagDeobfus.py     pass orchestration - never executes input
    PlagFold.py        folds expressions in place using the static evaluator
    PlagEval.py        recursive-descent evaluator over a restricted subset
    PlagTokens.py      tokenizer shared by the evaluator
    PlagTrace.py       sequential variable tracking through reassignment
    PlagVbs.py         VBScript literal folding
    PlagJs.py          JScript literal folding
    PlagCmd.py         batch / cmd variable resolution
    PlagEncode.py      shared escape / base64 / percent decoding
    PlagLinks.py       deep links into each provider's own pages
    PlagGrep.py        indicator extraction + signature scanning
    PlagRules/         signature rule sets, MITRE-tagged (see note below)
    PlagProviders/     one threat-intel client per file
    PlagIntel.py       provider fan-out and cache orchestration
    PlagScope.py       what is worth querying, and why something was not
    PlagConfig.py      the single API-key / provider registry
    PlagStore.py       SQLite: analyses, findings, per-source intel, settings
    PlagBatch.py       bounded multi-file and archive extraction
    PlagEngine.py      the pipeline - shared by both front ends
    PlagReport.py      PDF rendering (front matter, findings, appendices)
    PlagCharts.py      matplotlib charts for the report
    PlagMitre.py       technique ID -> human-readable name
    PlagExplain.py     plain-English notes for each transform
    PlagFilter.py      upload validation and filename sanitization
  PlagWeb/             Flask dashboard - routes, templates, static assets
  PlagCLI.py           Click CLI
plaguardsv2-cli.py     thin root entry point
```

### Why the rules and a few other modules are split across many small files

While this was being built, local antivirus real-time protection repeatedly quarantined source files that gathered several "AV-evasion technique" keywords in one place — AMSI references, reflective assembly loading and Defender-tampering commands together read like a loader cheat sheet to a heuristic scanner. The very content that makes the tool useful for detection makes its *source* look suspicious.

Splitting the rule set and a few similarly dense modules into small, single-purpose files resolved it without changing any detection logic. If you hit the same problem while extending the rules or providers, keep new files small and focused, and consider a Defender exclusion for the project folder.

## Safety & privacy

- Submitted scripts are **never executed or evaluated**. Deobfuscation is pure text transformation, and the evaluator folds literals only.
- **No script content leaves your machine.** Only extracted indicator values — a hash, IP, domain or URL — are sent to providers you configured, and never the surrounding context.
- Deobfuscation, indicator matching, storage and PDF generation are **fully offline**.
- Reports are an **investigative aid, not a verdict.** Deobfuscation is best-effort and the transform log states exactly what was applied; threat-intel results reflect third-party data at query time. The analyst's triage decision is the authoritative call.
- Indicators are **defanged** in every report so nothing in a document you circulate is clickable, and can be redacted entirely before sharing.

## Credits

Built by **quifl** — [github.com/quifl](https://github.com/quifl) · [github.com/tkxldk](https://github.com/tkxldk)

On the foundation laid by **Plaguards v1** — [github.com/baycysec/plaguards](https://github.com/baycysec/plaguards).
