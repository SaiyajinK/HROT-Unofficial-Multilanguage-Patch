param([string]$Language = '')

# HROT external language patcher (offline, Windows PowerShell 5.1).
# Only generates HROT_localized.exe; HROT.exe is never written.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Local = Join-Path $Root 'local'
$Source = Join-Path $Root 'HROT.exe'
$Destination = Join-Path $Root 'HROT_localized.exe'

function Read-U16([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt16($Data, $Offset)
}
function Read-U32([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt32($Data, $Offset)
}
function Write-U16([byte[]]$Data, [int]$Offset, [uint16]$Value) {
    [BitConverter]::GetBytes($Value).CopyTo($Data, $Offset)
}
function Write-U32([byte[]]$Data, [int]$Offset, [uint32]$Value) {
    [BitConverter]::GetBytes($Value).CopyTo($Data, $Offset)
}
function Align-To([long]$Value, [long]$Alignment) {
    if ($Alignment -le 0) { throw 'Invalid alignment' }
    return [long]([Math]::Ceiling($Value / $Alignment) * $Alignment)
}

try {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw 'HROT.exe missing. Copy the contents of this patch into the HROT game folder.'
    }
    $languages = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $Local 'languages.txt'), [Text.Encoding]::UTF8)) {
        if ($line -match '^([0-9]{2})\|([a-z0-9-]+)\|(.+)$') {
            $languages.Add([pscustomobject]@{ Number = $matches[1]; Code = $matches[2]; Name = $matches[3] })
        }
    }
    if ($languages.Count -ne 30) { throw 'Invalid language manifest.' }

    # Always ask on each run; do not reuse an old selected_language.txt.
    if (-not $Language) {
        Write-Host "`nHROT - Choix de langue / Language selection`n"
        foreach ($item in $languages) { Write-Host ("{0}. {1} ({2})" -f $item.Number, $item.Name, $item.Code) }
        $choice = Read-Host "`nNumero de langue / Language number"
        if (-not $choice) { $Language = 'fr' }
        else {
            $selected = @($languages | Where-Object { $_.Number -eq $choice.PadLeft(2,'0') })
            if (-not $selected) { throw 'Invalid language selection.' }
            $Language = $selected[0].Code
        }
    }
    $Language = $Language.Trim().ToLowerInvariant()
    if (-not ($languages | Where-Object { $_.Code -eq $Language })) {
        throw "Unknown language: $Language"
    }

    $iniPath = Join-Path $Local ($Language + '.ini')
    if (-not (Test-Path -LiteralPath $iniPath)) { throw "Missing language file: $iniPath" }
    $translations = @{}
    foreach ($line in [IO.File]::ReadAllLines($iniPath, [Text.Encoding]::UTF8)) {
        if ($line -match '^([0-9]{3})=(.*)$') {
            $id = [int]$matches[1]
            if ($id -lt 1 -or $id -gt 619) { throw "Unknown text ID: $id" }
            $translations[$id] = $matches[2]
        }
    }

    if ($translations.Count -eq 0) {
        throw "No translated entries in $Language.ini; localized executable not generated."
    }

    $Bytes = [IO.File]::ReadAllBytes($Source)
    $expected = [IO.File]::ReadAllText((Join-Path $Local 'target_sha256.txt'), [Text.Encoding]::ASCII).Trim().ToLowerInvariant()
    $hashAlgo = [System.Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($hashAlgo.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
    finally { $hashAlgo.Dispose() }
    if ($actual -ne $expected) {
        throw "Unsupported HROT.exe build. Expected SHA256 $expected, got $actual. Original left untouched."
    }

    $pe = [int](Read-U32 $Bytes 0x3C)
    if ((Read-U32 $Bytes $pe) -ne 0x00004550) { throw 'Invalid PE signature.' }
    $sectionCount = [int](Read-U16 $Bytes ($pe + 6))
    if ($sectionCount -ne 9) { throw 'Unexpected PE section count.' }
    $optional = $pe + 24
    if ((Read-U16 $Bytes $optional) -ne 0x10B) { throw 'Expected 32-bit PE.' }
    $imageBase = [uint64](Read-U32 $Bytes ($optional + 28))
    $sectionAlignment = [long](Read-U32 $Bytes ($optional + 32))
    $fileAlignment = [long](Read-U32 $Bytes ($optional + 36))
    $headers = $optional + [int](Read-U16 $Bytes ($pe + 20))
    $newHeader = $headers + $sectionCount * 40
    $headerLimit = [int](Read-U32 $Bytes ($optional + 60))
    if (($newHeader + 40) -gt $headerLimit) { throw 'No room for a PE section header.' }

    $lastHeader = $headers + ($sectionCount - 1) * 40
    $lastVirtualSize = [long](Read-U32 $Bytes ($lastHeader + 8))
    $lastRva = [long](Read-U32 $Bytes ($lastHeader + 12))
    $lastRawSize = [long](Read-U32 $Bytes ($lastHeader + 16))
    $lastRawStart = [long](Read-U32 $Bytes ($lastHeader + 20))
    if ($lastRawStart + $lastRawSize -ne $Bytes.Length) { throw 'Unexpected PE overlay.' }
    $newRva = Align-To ($lastRva + $lastVirtualSize) $sectionAlignment
    $newRawStart = Align-To $Bytes.Length $fileAlignment

    # Indexed pointer locations for the exact checked game version.
    $pointerMap = @{}
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $Local 'strings.map'), [Text.Encoding]::ASCII)) {
        if ($line -match '^([0-9]{3})\|([0-9A-F]+)\|([0-9A-F]+)$') {
            $id = [int]$matches[1]
            $pos = [Convert]::ToInt32($matches[2], 16)
            $oldVA = [Convert]::ToUInt32($matches[3], 16)
            if ((Read-U32 $Bytes $pos) -ne $oldVA) { throw "Pointer mismatch at $pos." }
            if (-not $pointerMap.ContainsKey($id)) {
                $pointerMap[$id] = New-Object 'System.Collections.Generic.List[object]'
            }
            $pointerMap[$id].Add([pscustomobject]@{ Offset = $pos; OldVA = $oldVA })
        }
    }
    if ($pointerMap.Count -ne 619) { throw 'String pointer map is incomplete.' }

    $encoder = [Text.Encoding]::GetEncoding(1250, [Text.EncoderExceptionFallback]::new(), [Text.DecoderExceptionFallback]::new())
    $payload = New-Object 'System.Collections.Generic.List[byte]'
    $newPointers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($id in ($translations.Keys | Sort-Object)) {
        $value = [string]$translations[$id]
        if (-not $value) { continue }
        try { [byte[]]$encoded = $encoder.GetBytes($value) }
        catch { throw "Translation #$id contains characters unsupported by HROT's legacy Czech encoding (CP1250)." }
        while (($payload.Count % 4) -ne 0) { $payload.Add(0) }
        $start = $payload.Count
        $payload.AddRange([byte[]](255,255,255,255)) # Delphi static AnsiString reference count -1
        $payload.AddRange([BitConverter]::GetBytes([uint32]$encoded.Length))
        $payload.AddRange($encoded)
        $payload.Add(0)
        while (($payload.Count % 4) -ne 0) { $payload.Add(0) }
        $newPointer = [uint32]($imageBase + $newRva + $start + 8)
        foreach ($pointer in $pointerMap[$id]) {
            $newPointers.Add([pscustomobject]@{Offset = $pointer.Offset; Pointer = $newPointer})
        }
    }
    # The native language selector uses a standalone 'English' AnsiString.
    # Update its displayed label for the selected translation only.
    # HROT does not support every Unicode glyph; use safe native names or romanization.
    # The original 'lan_en' token is deliberately not changed.
    $languageLabels = @{
        'fr' = 'Francais'
        'en' = 'English'
        'de' = 'Deutsch'
        'es' = 'Espanol'
        'it' = 'Italiano'
        'pt' = 'Portugues'
        'pt-br' = 'Portugues (Brasil)'
        'ru' = 'Russkiy'
        'ja' = 'Nihongo'
        'ko' = 'Hangugeo'
        'zh-cn' = 'Jianti Zhongwen'
        'zh-tw' = 'Fanti Zhongwen'
        'pl' = 'Polski'
        'tr' = 'Turkce'
        'nl' = 'Nederlands'
        'bg' = 'Balgarski'
        'cs' = 'Česky'
        'da' = 'Dansk'
        'el' = 'Ellinika'
        'fi' = 'Suomi'
        'hu' = 'Magyar'
        'id' = 'Bahasa Indonesia'
        'no' = 'Norsk'
        'ro' = 'Romana'
        'sv' = 'Svenska'
        'th' = 'Phasa Thai'
        'uk' = 'Ukrainska'
        'vi' = 'Tieng Viet'
        'es-419' = 'Espanol (LatAm)'
        'ms' = 'Bahasa Melayu'
    }
    $labelPointerOffset = 0x94886A
    $expectedLabelPointer = [uint32]0x00D4AC38
    if ((Read-U32 $Bytes $labelPointerOffset) -ne $expectedLabelPointer) {
        throw 'Original English language label differs from the verified game build.'
    }
    $languageLabel = [string]$languageLabels[$Language]
    if (-not $languageLabel) { throw "Missing display label for $Language." }
    [byte[]]$labelBytes = $encoder.GetBytes($languageLabel)
    while (($payload.Count % 4) -ne 0) { $payload.Add(0) }
    $labelStart = $payload.Count
    $payload.AddRange([byte[]](255,255,255,255))
    $payload.AddRange([BitConverter]::GetBytes([uint32]$labelBytes.Length))
    $payload.AddRange($labelBytes)
    $payload.Add(0)
    $newPointers.Add([pscustomobject]@{
        Offset = $labelPointerOffset
        Pointer = [uint32]($imageBase + $newRva + $labelStart + 8)
    })
    if ($payload.Count -eq 0) { throw 'Selected translation contains no usable text.' }
    $rawSize = Align-To $payload.Count $fileAlignment
    $newImageSize = Align-To ($newRva + $payload.Count) $sectionAlignment

    [byte[]]$patched = New-Object byte[] ($newRawStart + $rawSize)
    [Array]::Copy($Bytes, 0, $patched, 0, $Bytes.Length)
    [Array]::Copy($payload.ToArray(), 0, $patched, [int]$newRawStart, $payload.Count)
    foreach ($change in $newPointers) {
        Write-U32 $patched $change.Offset $change.Pointer
    }
    # New read-only initialized-data section, outside all original game sections.
    $name = [Text.Encoding]::ASCII.GetBytes('HROTLOC')
    [Array]::Copy($name, 0, $patched, $newHeader, $name.Length)
    Write-U32 $patched ($newHeader + 8) ([uint32]$payload.Count)
    Write-U32 $patched ($newHeader + 12) ([uint32]$newRva)
    Write-U32 $patched ($newHeader + 16) ([uint32]$rawSize)
    Write-U32 $patched ($newHeader + 20) ([uint32]$newRawStart)
    Write-U32 $patched ($newHeader + 36) ([uint32]0x40000040)
    Write-U16 $patched ($pe + 6) ([uint16]($sectionCount + 1))
    Write-U32 $patched ($optional + 56) ([uint32]$newImageSize)
    Write-U32 $patched ($optional + 64) ([uint32]0) # optional PE checksum

    [IO.File]::WriteAllBytes($Destination, $patched)
    Write-Host ("Textes modifies / Patched texts: {0} ; references: {1} ; langue: {2}" -f $translations.Count, $newPointers.Count, $Language)
    Write-Host 'HROT.exe original non modifie / Original HROT.exe unchanged.'
    Write-Host ("Dans les options de HROT, choisissez {0} (remplace English)." -f $languageLabel)

    Write-Host 'HROT_localized.exe genere / generated. Launch it from Steam when ready.'
}
catch {
    Write-Host ("`nERROR: " + $_.Exception.Message) -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}
