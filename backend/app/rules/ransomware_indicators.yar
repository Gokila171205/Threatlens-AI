rule Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Detects attempts to delete volume shadow copies using vssadmin or wmic"
        author = "ThreatLens AI Research"
        severity = "critical"
        technique = "T1490"
    strings:
        $vss = "vssadmin" nocase
        $del = "delete shadows" nocase
        $wmic = "wmic shadowcopy delete" nocase
    condition:
        ($vss and $del) or $wmic
}
