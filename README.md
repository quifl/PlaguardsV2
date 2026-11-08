# PlaguardsV2

**Static deobfuscation and IOC triage for blue teams.**

<p align="center">
<img src="plaguardsv2/PlagWeb/static/assets/PlaguardsBanner.png" width="620" alt="PlaguardsV2">
</p>

<p align="center">
 <a href="#"><img src="https://img.shields.io/badge/Static_Deobfuscator-blue"></a>
 <a href="#"><img src="https://img.shields.io/badge/IOC_Lookup-red"></a>
 <a href="#"><img src="https://img.shields.io/badge/Automated_Reporting-white"></a>
 <a href="#"><img src="https://img.shields.io/badge/IP_Geolocation-2e7d32"></a>
 <a href="#"><img src="https://img.shields.io/badge/7_Threat_Intel_Providers-c81e4a"></a>
 <a href="https://github.com/baycysec/plaguards"><img src="https://img.shields.io/badge/Built_on-Plaguards_v1-640D5F"></a>
</p>

You give PlaguardsV2 a suspicious script. It gives you back the script in
readable form, the indicators hidden in it (URLs, IPs, domains, hashes and
more), what your threat-intel services know about them, and a report you can
hand to someone else. It runs on your own machine and never runs the script.

[Quick start](#quick-start) ·
[How it works](#how-it-works) ·
[What it can read](#what-it-can-read) ·
[Dashboard](#using-the-dashboard) ·
[Command line](#using-the-command-line) ·
[Optional setup](#optional-setup) ·
[Safety and privacy](#safety-and-privacy) ·
[Troubleshooting](#troubleshooting) ·
[Changelog](CHANGELOG.md)

> [!IMPORTANT]
> **Nothing you submit is ever executed.** PlaguardsV2 only rewrites text: no
> `eval`, no sandbox, no PowerShell process. Deobfuscation, extraction,
> storage and reporting all work offline. The only thing that leaves your
> machine is an indicator value (a hash, IP, domain or URL) sent to a
> threat-intel provider you configured yourself.

## Quick start

You need Python 3.12 or newer. Docker is optional: without it, the installer
sets up a local virtual environment instead. The app uses port 8000.

**1. Get the code.**

```console
git clone https://github.com/quifl/PlaguardsV2.git
cd PlaguardsV2
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

The installer creates `.env` from `.env.example` if it is missing, uses Docker
if a Docker daemon is running and a local virtual environment otherwise,
starts the app, and opens `http://localhost:8000`.

**3. Try it.** On the dashboard, click **Run the example script**. It analyzes
the harmless demo script in `samples/` from start to finish, report included.

Threat-intel keys and geolocation databases are optional; see
[Optional setup](#optional-setup). Without them, deobfuscation and indicator
extraction work exactly the same.

## How it works

1. **It works out the language** of the input from its content (PowerShell,
   batch, JScript, VBScript or plain text), never from the file extension.
2. **It undoes the obfuscation step by step.** Split strings are joined,
   encoded data is decoded, character codes become characters, variables are
   replaced with their values, and so on, until nothing more changes.
3. **Code handed to another interpreter becomes its own layer.** If the
   script passes a string to `Invoke-Expression`, runs `powershell -enc`,
   calls `cmd /c`, or uses `eval` / `Execute`, that code is taken out, read
   with the rules of its own language, and shown under its own header. The
   parent keeps a `<<layer N>>` marker where it was.
4. **It extracts indicators from every layer** and records which layer each
   one came from.
5. **It checks the indicators** with the threat-intel providers you set up and
   locates every IP address.

Here is a small example. The input:

```powershell
$u = 'https://example.net/outer'
iex ('Write-Host ' + 'https://example.com/inner')
```

What PlaguardsV2 shows:

```text
$u = 'https://example.net/outer'
Invoke-Expression <<layer 2>>

==== layer 2 | powershell | from layer 1 | HANDOFF: Invoke-Expression ====
Write-Host https://example.com/inner
```

`https://example.net/outer` is reported from layer 1 and
`https://example.com/inner` from layer 2 (shown as layer path `1/2`).

Every change is written to a transform log, so you can see exactly what was
done. Anything worked out from an assumption, such as a batch variable that is
never set or a stock Windows value like `%COMSPEC%`, is marked as assumed.

Each run has safety limits: 50 MB of input, 200 MB of decoded data, layers up
to 12 deep, and compressed data that would grow more than 100 times its size
is not unpacked. When a run hits a limit, the run notes say which one and
where.

## What it can read

**PowerShell.** `-EncodedCommand` (including `-enc`, `-e`, `/enc` and
`-ArgumentList` arrays), Base64 with gzip or deflate stages, string
concatenation, `-join` / `-split` / `-replace`, the `-f` format operator,
`[char]` codes and arithmetic (`+ - * /`, `-bxor`), `$(...)` subexpressions,
`[Text.Encoding]::*.GetString`, `[byte[]]` arrays, backticks, `[string]`
casts, aliases (`iwr` becomes `Invoke-WebRequest`), typographic quotes and
dashes, and variables traced through reassignments. `Invoke-Expression`,
`[ScriptBlock]::Create` and nested `powershell -Command` calls become layers.

**Batch and cmd.** Read in cmd.exe's own parsing order: `%var%` expansion
with substring (`%var:~start,len%`) and replace (`%var:str=repl%`) forms,
carets and quotes, delayed `!var!` expansion, `call set`, `set /a`, and
`FOR /F` over a literal string or `FOR /L` ranges. `cmd /c`, `mshta
javascript:` / `vbscript:` and `powershell` calls become layers. A `FOR /F`
over a command's output is recorded, never run.

**JScript.** `String.fromCharCode` with arithmetic, `atob`, `unescape`, hex
and unicode escapes, Base64, `split` / `reverse` / `join`, `replace`,
`substring` / `substr` / `slice` / `charAt`, `obj['name']` as `obj.name`, and
variable propagation. `eval`, `new Function`, `setTimeout` with a string, and
`execScript` become layers.

**VBScript.** `Chr()` with arithmetic, `&` and `+` concatenation,
`StrReverse`, `Replace`, `Split` / `Join`, `Mid` / `Left` / `Right`, `UCase` /
`LCase` / `Trim`, Base64, line continuations, and variable propagation.
`Execute`, `ExecuteGlobal` and `Eval` become layers.

**Droppers.** A JScript or VBScript file that starts `powershell -enc ...`
through `WScript.Shell` gets the PowerShell stage decoded as its own layer.

**Logs and raw data.** A line that is entirely a Base64 blob or a list of
character codes is decoded in place.

**Anything else encoded.** When the passes above are finished, a recipe search
modelled on CyberChef's Magic tries Base32/58/64/85, hex, decimal, octal,
binary, URL and HTML-entity encoding, escapes, quoted-printable,
gzip/zlib/deflate/bzip2/LZMA, UTF-16, single-byte XOR, ROT13/47 and reversal,
combined up to four steps deep. Every step is a real CyberChef operation, so
each recipe opens in CyberChef unchanged.

### Indicators it finds

- IPv4 and IPv6 addresses, domains, URLs, email addresses, and MD5, SHA-1 and
  SHA-256 hashes, including defanged forms such as `1[.]2[.]3[.]4` and
  `hxxp://`.
- Registry keys, mutexes, User-Agents, `ip:port` pairs, crypto wallets,
  Windows and UNC paths, and scheduled task and service names, including ones
  assembled while the script runs.
- Signatures for download cradles, in-memory execution, living-off-the-land
  binaries, persistence, AMSI references and hidden windows, each tagged with
  its MITRE ATT&CK technique.

## Using the dashboard

| Page | What you do there |
|---|---|
| **Analyze** | Paste a script, or drop files anywhere on the page: `.ps1 .txt .vbs .js .bat .cmd .log` or a `.zip` (up to 200 files, 5 MB each, 100 MB per submission). Several files can produce separate reports or one combined document. The second card, **Quick IOC Lookup**, checks a single indicator; leave the type on *Detect automatically*, or pick IP, Domain, URL, File hash or Malware signature / family (a family name such as `AgentTesla` can only be looked up by picking the type). |
| **Result** | The readable script (every layer under its own header, with a table of layers), the transform log, resolved variables, encoded runs with the recipe that opens each, and the original input on the left. Findings with context, MITRE mapping, threat intel and triage buttons on the right. Mark each finding Confirmed Threat, False Positive or Unknown, one at a time or all at once. Export the findings as PDF, Excel or CSV. |
| **History** | Past analyses, newest first, with completion time, duration and status. A batch upload is one entry you can expand. Select rows to export a zip of PDFs, build one combined report, or delete them. How many analyses are kept is set in Settings. |
| **Tutorial** | Every page explained, plus a guided tour of the app. |
| **Settings** | API keys, the three GeoLite2 database paths, the offline CyberChef status, how much history to keep, the analyst name printed on reports, the UTC offset for timestamps, and a button that clears stored history. |

**Reports.** The PDF has a cover, clickable contents with page numbers, a
disclaimer, a summary with charts, the findings table and detail, the
transform log, resolved variables, and both scripts in full. When the input
had more than one layer, it also has a "Layers of the input" section, and the
Excel file a Layers sheet. Indicators are defanged everywhere so nothing in a
report is clickable, and you can redact them before sharing. Severity
describes the technique observed, not confirmed impact.

The dashboard and the command line share one engine and one database: a
script analyzed in the terminal shows up in History, and a verdict recorded in
the browser appears in a report made later from the command line.

## Using the command line

```console
python plaguardsv2-cli.py analyze <path|->     # a file, or '-' (or nothing) for stdin
    --pdf out.pdf                              # write a PDF report
    --json out.json                            # write the results as JSON
    --redact-iocs                              # black out indicator values in the PDF
    --triage                                   # mark each finding interactively
    --no-intel                                 # skip all threat-intel providers
    --no-cache                                 # ignore the local threat-intel cache
    --no-store                                 # don't save this analysis
    --db-path FILE                             # use a different database file
    --explain                                  # print the layer tree and its provenance JSON
    --max-depth N                              # deepest layer to open (default 12)
    --legacy-pipeline                          # use the previous single-text engine

python plaguardsv2-cli.py list                 # show past analyses
```

## Optional setup

### Threat-intel providers

Add keys on the **Settings** page or in `.env`. A provider without a key is
skipped and its result is labelled `not_checked`.

| Provider | Env var | Get a key |
|---|---|---|
| VirusTotal | `VT_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| abuse.ch (MalwareBazaar / ThreatFox / URLhaus) | `ABUSECH_API_KEY` | https://auth.abuse.ch/ |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api |
| AlienVault OTX | `OTX_API_KEY` | https://otx.alienvault.com/api |
| Shodan | `SHODAN_API_KEY` | https://account.shodan.io/ |
| GreyNoise (Community) | `GREYNOISE_API_KEY` | https://viz.greynoise.io/account/ |
| Pulsedive | `PULSEDIVE_API_KEY` | https://pulsedive.com/api/ |
| ipinfo.io *(geolocation)* | `IPINFO_TOKEN` | https://ipinfo.io/account/token |

Providers are queried in parallel, one request at a time each, so every
provider's rate limit is respected. VirusTotal's free tier allows 4 requests a
minute; with a premium key, set `VT_REQUESTS_PER_MINUTE` in `.env`. Answers are
cached for a day, so analyzing a sample again costs no quota. Reserved and
private addresses are marked *not applicable* instead of being looked up.

> [!WARNING]
> Keys are stored in the local SQLite database on the machine running
> PlaguardsV2. Never commit `.env`, and never put keys in source code.

### IP geolocation

Each address gets its country, region, city, coordinates with an accuracy
radius, ASN and network operator, time zone and reverse DNS. Local MaxMind
GeoLite2 databases are preferred because the lookup never leaves your machine.
In **Settings → Geolocation Databases**, fill in any of City, Country and ASN
with a `.mmdb` file, a folder, or MaxMind's `.tar.gz` download (it is unpacked
for you). That section also explains how to get the databases free from
[MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
Without them, ipinfo.io is used if you set `IPINFO_TOKEN`.

### Offline CyberChef

```console
python tools/fetch_cyberchef.py              # latest release
python tools/fetch_cyberchef.py --version v11.5.0
```

This downloads [GCHQ's CyberChef](https://github.com/gchq/CyberChef), checks
it against the SHA-256 GitHub publishes, and installs it into
`plaguardsv2/PlagWeb/cyberchef/`. Restart the app and the Result page gets a
**CyberChef** button on every encoded run, opening CyberChef with the recipe
already loaded. Your copy is served by PlaguardsV2 at `/cyberchef/`; the sample
travels in the URL fragment, which browsers never send to a server, and the
page cannot contact any other host. With Docker, run the fetch before
`docker compose up --build`.

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
pip install -r requirements.txt
flask --app plaguardsv2.PlagWeb run --debug
```

## Safety and privacy

- Submitted scripts are **never executed or evaluated**. The engine only
  rewrites literal text.
- **Script content never leaves your machine.** Only an indicator value is
  sent, and only to providers you configured.
- Deobfuscation, indicator matching, storage and PDF generation work
  **fully offline**.
- The optional CyberChef is a local copy served by PlaguardsV2, never the
  public site.
- Reports are an **aid to investigation, not a verdict.** Deobfuscation is
  best effort and the transform log shows exactly what was done; threat-intel
  results reflect the providers' data at the time of the lookup. Your triage
  decision is the final call.

## Troubleshooting

**My antivirus quarantined a file from this project.** PlaguardsV2 contains
detection rules and decoders for the same tricks malware uses, and some
real-time scanners react to that. The rule set is split into small files to
avoid it, but if it happens, add an exclusion for the project folder.

**The installer did not use Docker.** It uses Docker only when the Docker
daemon is running; otherwise it falls back to a local virtual environment.
Start Docker and run the installer again if you want the container.

**A finding says `not_checked`.** That provider has no API key. Add one in
Settings.

**The output says a limit was reached.** A stage was not opened because of a
safety limit (depth, size or inflation ratio). The run notes name the limit.
From the command line, `--max-depth` changes the depth limit.

<details>
<summary><b>Project layout</b></summary>

```text
plaguardsv2/
  GuardModules/        the engine
    PlagEngine.py        the pipeline shared by the dashboard and the CLI
    PlagLayered.py       layers: the artifact tree, scheduling, checks and limits
    PlagRouter.py        works out each layer's language
    PlagDeobfus.py       the PowerShell passes (and the previous engine)
    PlagCmdParse.py      batch files in cmd.exe's parsing order
    PlagPsHandoff.py     Invoke-Expression, ScriptBlock and nested powershell stages
    PlagShellArgs.py     -EncodedCommand / -Command arguments as the shell reads them
    PlagJsLayer.py       JScript stages and folds;  PlagVbsLayer.py  the same for VBScript
    PlagMagic.py         the CyberChef-style recipe search
    PlagGrep.py          indicator extraction and signature scanning (rules in PlagRules/)
    PlagIntel.py         threat-intel lookups (one client per provider in PlagProviders/)
    PlagGeo.py           IP geolocation
    PlagStore.py         the SQLite database
    PlagReport.py        PDF reports;  PlagTable.py  CSV and Excel
  PlagWeb/             the Flask dashboard
  PlagCLI.py           the command line
plaguardsv2-cli.py     command-line entry point
samples/               a harmless example script
tools/
  fetch_cyberchef.py   installs the optional offline CyberChef
```

</details>

## Credits

Built by **quifl**. [github.com/quifl](https://github.com/quifl) · [github.com/tkxldk](https://github.com/tkxldk)

On the foundation laid by **Plaguards v1**: [github.com/baycysec/plaguards](https://github.com/baycysec/plaguards).
IP geolocation is inspired by [HolmesGeo](https://github.com/jon-brandy/HolmesGeo).

The optional offline decoder is [CyberChef](https://github.com/gchq/CyberChef) by GCHQ, Apache License 2.0. It is downloaded at install time, not redistributed in this repository.
