"""Rule set: dynamic-evaluation / flag-based execution patterns."""
from ..regex_utils import abbreviated_flag

RULES = [
    dict(name="Invoke-Expression / IEX usage", pattern=r"\b(?:Invoke-Expression|IEX)\b",
         mitre=["T1059.001"], severity="medium",
         description="Dynamically evaluates a string as PowerShell code."),
    dict(name="Hidden/bypass execution flags",
         pattern=r"-(?:W(?:indowStyle)?\s+Hidden|NoP(?:rofile)?|NonI(?:nteractive)?|Ep\s+Bypass|ExecutionPolicy\s+Bypass)",
         mitre=["T1059.001", "T1564.003"], severity="medium",
         description="Flags commonly used to run PowerShell silently and skip prompts."),
    dict(name="Base64-encoded command",
         pattern="-" + abbreviated_flag("encodedcommand") + r"\s+[A-Za-z0-9+/]{16,}={0,2}",
         mitre=["T1027", "T1140"], severity="medium",
         description="Script passed as a Base64 blob rather than plaintext."),
]
