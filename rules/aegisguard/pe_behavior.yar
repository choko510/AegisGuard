// AegisGuard self-authored rules. Text-only, no includes, no imports.

rule AG_PE_Embedded_Encoded_PowerShell
{
    meta:
        id = "AG-0101"
        version = 1
        severity = 40
        description = "PE file embeds a PowerShell -EncodedCommand invocation"
        author = "AegisGuard project"
        origin = "self-authored"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc = "-EncodedCommand" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 64MB and $ps and $enc
}
