param([int]$IntervalMs = 250)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$rootPath = 'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
function Decode-Name([string]$value) {
    -join ($value.ToCharArray() | ForEach-Object {
        $c = [int]$_
        if ($c -ge 65 -and $c -le 90) { [char](65 + ($c - 65 + 13) % 26) }
        elseif ($c -ge 97 -and $c -le 122) { [char](97 + ($c - 97 + 13) % 26) }
        else { $_ }
    })
}
function Read-Entries {
    $entries = @{}
    $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($rootPath)
    if ($null -eq $root) { throw 'UserAssist key is absent for this account' }
    try {
        foreach ($group in $root.GetSubKeyNames()) {
            $key = $root.OpenSubKey("$group\Count")
            if ($null -eq $key) { continue }
            try {
                foreach ($name in $key.GetValueNames()) {
                    $bytes = $key.GetValue($name)
                    if ($bytes -isnot [byte[]]) { continue }
                    $id = "$group/$name"
                    $entries[$id] = @{ group = $group; name = $name; bytes = $bytes; fingerprint = [Convert]::ToBase64String($bytes) }
                }
            } finally { $key.Dispose() }
        }
    } finally { $root.Dispose() }
    return ,$entries
}
$before = Read-Entries
@{ source = 'userassist'; event = 'ready'; at = [DateTime]::UtcNow.ToString('o'); baseline = $before.Count; account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; intervalMs = $IntervalMs } | ConvertTo-Json -Compress
while ($true) {
    Start-Sleep -Milliseconds $IntervalMs
    try {
        $after = Read-Entries
        foreach ($id in $after.Keys) {
            $item = $after[$id]
            $old = $before[$id]
            if ($null -ne $old -and $old.fingerprint -eq $item.fingerprint) { continue }
            $record = [ordered]@{ source = 'userassist'; event = 'changed'; at = [DateTime]::UtcNow.ToString('o'); group = $item.group; name = (Decode-Name $item.name); bytes = $item.bytes.Length; new = ($null -eq $old) }
            if ($item.bytes.Length -eq 72) {
                $record.count = [BitConverter]::ToUInt32($item.bytes, 4)
                $record.previousCount = if ($null -ne $old -and $old.bytes.Length -eq 72) { [BitConverter]::ToUInt32($old.bytes, 4) } else { $null }
                $record.focusCount = [BitConverter]::ToUInt32($item.bytes, 8)
                $record.focusMs = [BitConverter]::ToUInt32($item.bytes, 12)
                $filetime = [BitConverter]::ToInt64($item.bytes, 60)
                $record.lastRun = if ($filetime -gt 0) { try { [DateTime]::FromFileTimeUtc($filetime).ToString('o') } catch { $null } } else { $null }
                $record.layout = '72-byte candidate, undocumented'
            }
            $record | ConvertTo-Json -Compress
        }
        $before = $after
    } catch {
        @{ source = 'userassist'; event = 'error'; at = [DateTime]::UtcNow.ToString('o'); error = $_.Exception.Message } | ConvertTo-Json -Compress
    }
}
