rule EICAR_Test_Rule {
    meta:
        description = "Harmless EICAR Standard Anti-Virus Test File signature"
        author = "ThreatLens AI"
        severity = "low"
        reference = "https://www.eicar.org"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $eicar
}
