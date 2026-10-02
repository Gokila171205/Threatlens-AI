rule Suspicious_PowerShell_Execution {
    meta:
        description = "Detects obfuscated or hidden PowerShell execution commands"
        author = "ThreatLens AI Research"
        severity = "high"
        technique = "T1059.001"
    strings:
        $ps1 = "powershell" nocase
        $enc = "-encodedcommand" nocase
        $enc_short = "-enc" nocase
        $hidden = "-windowstyle hidden" nocase
        $bypass = "-executionpolicy bypass" nocase
    condition:
        $ps1 and ($enc or $enc_short or ($hidden and $bypass))
}
