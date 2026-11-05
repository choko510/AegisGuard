// AegisGuard self-authored rules. Text-only, no includes, no imports.
// Matches are investigation leads, never proof of malware.

rule AG_Script_Defender_Exclusion
{
    meta:
        id = "AG-0001"
        version = 1
        severity = 60
        description = "Script adds a Microsoft Defender exclusion"
        author = "AegisGuard project"
        origin = "self-authored"
    strings:
        $cmd = "Add-MpPreference" ascii wide nocase
        $opt = /-Exclusion(Path|Process|Extension|IpAddress)/ ascii wide nocase
    condition:
        filesize < 4MB and $cmd and $opt
}

rule AG_Script_Browser_Credential_Upload
{
    meta:
        id = "AG-0002"
        version = 1
        severity = 75
        description = "Browser credential store name together with an upload call"
        author = "AegisGuard project"
        origin = "self-authored"
    strings:
        $store1 = "Login Data" ascii wide
        $store2 = "logins.json" ascii wide
        $store3 = "key4.db" ascii wide
        $send1 = "requests.post" ascii wide
        $send2 = "Invoke-RestMethod" ascii wide nocase
        $send3 = "UploadData" ascii wide
    condition:
        filesize < 4MB and any of ($store*) and any of ($send*)
}

rule AG_Script_Certutil_Download
{
    meta:
        id = "AG-0003"
        version = 1
        severity = 45
        description = "certutil used to download content"
        author = "AegisGuard project"
        origin = "self-authored"
    strings:
        $tool = "certutil" ascii wide nocase
        $flag = "-urlcache" ascii wide nocase
    condition:
        filesize < 4MB and $tool and $flag
}
