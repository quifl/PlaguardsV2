"""Rule set: outbound-network / remote-staging patterns."""

RULES = [
    dict(name="Remote download cradle",
         pattern=r"\b(?:DownloadString|DownloadFile|DownloadData|Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod)\b",
         mitre=["T1105"], severity="high",
         description="Fetches remote content, often the next stage of a payload."),
    dict(name="Raw socket networking", pattern=r"Net\.Sockets\.TCPClient",
         mitre=["T1071", "T1095"], severity="high",
         description="Raw TCP socket creation, sometimes used for shells."),
]
