# Changelog

What changed in PlaguardsV2, newest first. Dates are when the change reached
this repository.

## 2026-11-08: Layered deobfuscation

### New

- **Layers.** When a script hands code to another interpreter, that code is
  now opened as its own layer instead of being pasted back into the parent.
  This covers `-EncodedCommand`, `powershell -Command`, `Invoke-Expression`
  (including `& (Get-Command iex)`), `[ScriptBlock]::Create`, `NewScriptBlock`,
  `[scriptblock]` casts, `cmd /c`, `mshta javascript:` / `vbscript:`, JScript
  `eval` / `new Function` / `setTimeout` / `execScript`, VBScript `Execute` /
  `ExecuteGlobal` / `Eval`, and Base64 or compressed data that decodes to a
  script. The parent keeps a `<<layer N>>` marker where the stage was.
- **Each layer is read in its own language.** PowerShell rules no longer
  rewrite a batch file, and batch rules no longer touch PowerShell.
- **Every indicator says which layer it came from.** The Result page shows a
  layer badge on findings below the first layer, the PDF gets a "Layers of the
  input" section, and the Excel export gets a Layers sheet.
- **Batch files are read the way cmd.exe reads them:** carets and quotes,
  `%var%` and `!var!` expansion, `%var:~a,b%` and `%var:x=y%`, `call set`,
  `set /a` with 32-bit arithmetic, `setlocal` / `endlocal`, `goto`, and
  `FOR /F` over a literal string or `FOR /L` ranges. A `FOR /F` over a
  command's output is recorded, never run. A `cmd /c` stage sees the variables
  its parent set.
- **PowerShell:** typographic quotes and dashes are read as plain ones,
  built-in aliases and the script's own `Set-Alias` names are expanded
  (`iwr` becomes `Invoke-WebRequest`), `& 'name'` becomes `name`, and
  `-ArgumentList '-nop','-enc','...'` arrays and `/enc` switches are
  understood.
- **JScript:** `obj['name']` reads as `obj.name`, and `"abc"[1]` and
  `"a".concat("b")` fold to plain strings.
- **VBScript:** ` _` line continuations are joined, and `"a" + "b"` and
  `"a" & vbCrLf` fold to plain strings.
- **Droppers:** a JScript or VBScript file that runs `powershell -enc ...`
  through `WScript.Shell` gets the PowerShell stage decoded as its own layer.
- **Command line:** `--explain` prints the layer tree and its provenance as
  JSON, `--max-depth N` limits how deep layers are opened (default 12), and
  `--legacy-pipeline` runs the previous engine.

### Changed

- The layered engine is now the default. The previous engine is still
  available with `--legacy-pipeline` and produces exactly the output it did
  before.
- Safety limits for every run: 50 MB of input, 200 MB of decoded data in
  total, compressed data that would inflate more than 100 times its size is
  refused, layers stop at depth 12, a layer gets at most 20 rounds, and a run
  opens at most 2,000 layers. When a run hits a limit it says so in the run
  notes of the Result page and the report.
- Anything resolved from an assumption (an undefined batch variable, a stock
  Windows value, a case-insensitive match) is marked as assumed in the
  transform log.
- Uploaded files, CLI files and input piped to the CLI are decoded by their
  byte-order mark, and UTF-16 without one is recognised, so a script saved by
  PowerShell no longer reads as noise.
- Analyses saved by earlier versions still open; the database gains its new
  columns the first time it is opened.

### Fixed

- The Excel export no longer fails when a finding contains control
  characters.
- Compressed data is size-checked before it is inflated (64 MB cap), so a
  small input can no longer expand without bound.
- A script cannot plant text that imitates the engine's own markers to fake
  a layer or hide an indicator.

## 2026-10-24: CyberChef-style decoding and speed

- A recipe search modelled on CyberChef's Magic tries common encodings,
  compression, XOR and ROT on encoded runs the other passes leave, and names
  the recipe it used.
- Recipes open in a local copy of GCHQ CyberChef
  (`python tools/fetch_cyberchef.py`); samples never go to the public site.
- Faster: a 718 KB script went from 10.2 s to 0.7 s, and a single PDF report
  from 4.2 s to 2.7 s at about half the file size. Geolocation and
  threat-intel providers now run in parallel.
- `VT_REQUESTS_PER_MINUTE` raises the VirusTotal pace for premium keys. A
  provider answer that cannot be read costs one row, not the whole analysis.
- `.env` is loaded by every entry point, not only Docker.
- Settings checks GeoLite2 paths and can remove a saved key.
- The repository now holds only what you need to run PlaguardsV2.

## 2026-09-20: Timing and batches in History

- Every analysis records when it started, when it finished and how long it
  took. These appear on the Result page and in History, not in the PDF.
- A batch upload (several files, or a zip) is one History entry; expand it to
  see each file. One failing file no longer stops the rest.

## 2026-09-19: Accuracy

- Multi-stage Base64 no longer breaks from the second level onward. On a
  labelled set of 480 samples, complete recovery went from 27.5% to 100% and
  false indicators from 108 to zero.
- The PowerShell evaluator now handles hex and binary literals, `-replace` as
  a case-insensitive regex, `-f` format specifiers, modulo, `-shl` / `-shr` /
  `-bnot` and string indexing, and returns "unknown" instead of a wrong value.
- IPv6, crypto wallets, Windows and UNC paths, and scheduled task and service
  names are labelled properly in the dashboard and the report.

## 2026-09-18: Geolocation everywhere

- Settings takes GeoLite2 City, Country and ASN databases separately, each as
  a `.mmdb`, a folder or MaxMind's `.tar.gz`.
- Geolocation reaches the PDF report and Quick IOC Lookup.
- Providers without an API key are listed as "not checked" instead of being
  left out.

## 2026-08-15

- Byte-array loaders (Base64 to bytes, XOR with a key, then decompress) are
  recognised whatever their variable names, key length or operator shape.

## 2026-08-09: Geolocation and spreadsheet export

- Every indicator is checked with your threat-intel providers and every
  address located as part of the analysis.
- IP geolocation from a local MaxMind GeoLite2 database, or ipinfo.io with a
  token.
- Findings export as CSV and Excel, geolocation columns included.
- `Chr(71+1)` and `String.fromCharCode(0x6d, 108+1)` resolve.
- More VBScript (`Split`, `Join`, `Mid`, `Left`, `Right`, `UCase`, `LCase`,
  `Trim`) and JScript (`substring`, `substr`, `slice`, `charAt`, case, trim)
  string functions.
- Fixed four cases where a payload was decoded but no findings were reported.

## 2026-08-08: First release

- Static deobfuscation of PowerShell, VBScript, JScript and batch, plus
  encoded payloads in raw data and logs. Nothing submitted is executed.
- Indicator and signature extraction with MITRE ATT&CK mapping, defanging and
  analyst triage.
- Seven optional threat-intel providers with a local cache.
- PDF reports, separate or combined for a batch, with optional redaction.
- A web dashboard and a CLI sharing one engine and one database.
