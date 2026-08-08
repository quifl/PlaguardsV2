"""Rule set: living-off-the-land signed-binary execution proxies."""

RULES = [
    dict(name="Signed-binary proxy: certutil",
         pattern=r"\bcertutil\b[^\n]{0,40}-decode|\bcertutil\b[^\n]{0,40}-urlcache",
         mitre=["T1140", "T1105"], severity="medium",
         description="A trusted OS binary abused for decoding or download."),
    dict(name="Signed-binary proxy: mshta", pattern=r"\bmshta\b", mitre=["T1218.005"], severity="medium",
         description="A trusted OS binary used as an execution proxy."),
    dict(name="Signed-binary proxy: regsvr32", pattern=r"\bregsvr32\b", mitre=["T1218.010"], severity="medium",
         description="A trusted OS binary used as an execution proxy."),
    dict(name="Signed-binary proxy: rundll32", pattern=r"\brundll32\b", mitre=["T1218.011"], severity="medium",
         description="A trusted OS binary used as an execution proxy."),
    dict(name="Signed-binary proxy: bitsadmin", pattern=r"\bbitsadmin\b", mitre=["T1197"], severity="medium",
         description="Background transfer jobs abused for stealthy transfer."),
]
