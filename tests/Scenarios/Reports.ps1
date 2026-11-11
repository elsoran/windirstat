function Get-ReportSignature {
    param([object[]] $Rows, [string[]] $Fields)
    $signatures = foreach ($row in $Rows) {
        $values = [ordered]@{}
        foreach ($field in $Fields) { $values[$field] = [string]$row.$field }
        ConvertTo-Json $values -Compress
    }
    return @($signatures | Sort-Object)
}

function Test-DuplicateContent {
    param($Context, $Case)
    $root = New-TestTree
    foreach ($size in 0, 4096, 4097, 1MB, (1MB + 1)) {
        $first = New-TestFile (Join-Path $root "boundaries\$size-a.bin") $size (71 + $size)
        Copy-Item -LiteralPath $first -Destination (Join-Path $root "boundaries\$size-b.bin")
    }
    $first = New-TestFile (Join-Path $root 'full-hash\first.bin') 2MB 319
    $second = Join-Path $root 'full-hash\second.bin'
    $different = Join-Path $root 'full-hash\same-prefix-different-middle.bin'
    Copy-Item -LiteralPath $first -Destination $second
    Copy-Item -LiteralPath $first -Destination $different
    $locked = Join-Path $root 'full-hash\unreadable.bin'
    Copy-Item -LiteralPath $first -Destination $locked
    $stream = [IO.File]::Open($different, 'Open', 'ReadWrite')
    try { $stream.Position = 1MB + 211; $stream.WriteByte(0x17); $stream.WriteByte(0x25) }
    finally { $stream.Dispose() }
    $before = @(Get-ChildItem -LiteralPath $root -File -Recurse | Get-FileHash | Sort-Object Path)
    $groups = @($before | Group-Object Hash | Where-Object Count -GT 1)
    $expected = @($groups.Group.Path | Where-Object { $_ -ine $locked } |
        ForEach-Object { Get-NormalPath $_ } | Sort-Object)
    $runner = New-TestRunner @{ Options = @{ FileHashAlgorithm = $Case.Algorithm; SampleLargeFiles = 0 } }
    $unreadable = [IO.File]::Open($locked, 'Open', 'ReadWrite', [IO.FileShare]::Write)
    try {
        foreach ($format in 'csv', 'json') {
            $rows = Invoke-ScanReport $runner @($root) "duplicates-$format" -Kind Duplicates -Format $format
            Assert-Sequence @($rows.Name | ForEach-Object { Get-NormalPath $_ } | Sort-Object) $expected `
                'Whole-file duplicate verification handles size boundaries and excludes unreadable members'
            Assert-Equal @($rows | Where-Object { [string]$_.'Sampled Hash' -ine 'false' }).Count 0 `
                'Full-file duplicates are not labeled as sampled matches'
            foreach ($group in $groups) {
                $members = @($rows | Where-Object { (Get-NormalPath $_.Name) -in @($group.Group.Path |
                    ForEach-Object { Get-NormalPath $_ }) })
                Assert-Equal @($members.'Hash Prefix' | Sort-Object -Unique).Count 1 `
                    'Members of each independently verified duplicate group share their exported hash'
                if ($Case.Algorithm -eq 2) {
                    Assert-Equal ([string]$members[0].'Hash Prefix').ToUpperInvariant() $group.Name.Substring(0, 32) `
                        'The exported SHA-256 prefix matches the independently computed whole-file digest'
                }
            }
        }
    } finally { $unreadable.Dispose() }
    $after = @(Get-ChildItem -LiteralPath $root -File -Recurse | Get-FileHash | Sort-Object Path)
    Assert-Sequence @($after.Hash) @($before.Hash) 'Duplicate scanning preserves every source payload'
}

function Test-DuplicateBatchBoundaries {
    param($Context, $Case)
    $root = $Context.Fixture
    foreach ($count in 1, 127, 128, 129, 257) {
        for ($index = 0; $index -lt $count; ++$index) {
            New-TestFile (Join-Path $root ('files-{0:d3}\member-{1:d3}.bin' -f $count, $index)) `
                8193 (77 + $index % 5) | Out-Null
        }
    }
    foreach ($index in 1..7) { New-TestFile (Join-Path $root "unique-$index.bin") 8193 (4000 + $index) | Out-Null }
    $before = @(Get-ChildItem -LiteralPath $root -File -Recurse | Get-FileHash | Sort-Object Path)
    $groups = @($before | Group-Object Hash | Where-Object Count -GT 1)
    $expected = @($groups.Group.Path | Sort-Object)
    $runner = New-TestRunner @{ Options = @{
        ScanningThreads = $Case.Threads; FileHashAlgorithm = 2; SampleLargeFiles = 0
    } }
    foreach ($format in 'csv', 'json') {
        $rows = Invoke-ScanReport $runner @($root) "batch-boundaries-$format" -Kind Duplicates -Format $format
        Assert-Sequence @($rows.Name | Sort-Object) $expected `
            'Full and partial batches retain every matching file across directory and worker boundaries'
        foreach ($group in $groups) {
            $members = @($rows | Where-Object Name -In $group.Group.Path)
            Assert-Equal $members.Count $group.Count 'Each duplicate group contains every independently verified member'
            $hashes = @($members.'Hash Prefix' | ForEach-Object { $_.ToUpperInvariant() } | Sort-Object -Unique)
            Assert-Sequence $hashes @($group.Name.Substring(0, 32)) `
                'Each staged hash agrees with the independently computed SHA-256 digest'
        }
    }
    $rows = Invoke-ScanReport $runner @($root) 'batch-scan-results'
    Assert-Sequence @((Get-ReportFiles $rows).Name | Sort-Object) @($before.Path | Sort-Object) `
        'Batch publication includes each duplicate and unique file exactly once'
    Assert-Equal ([long]$rows[0].'Logical Size') ([long]$before.Count * 8193) `
        'Batch publication preserves recursive byte totals'
    Assert-Equal ([long]$rows[0].Folders) 5 'Batch publication preserves every directory'
    Assert-Sequence @(Get-ChildItem -LiteralPath $root -File -Recurse | Get-FileHash | Sort-Object Path |
        ForEach-Object Hash) @($before.Hash) 'Duplicate batching preserves every source payload'
}

function Test-SampledDuplicates {
    param($Context, $Case)
    $root = $Context.Fixture
    $exact = New-TestFile (Join-Path $root 'threshold-a.bin') 64MB -Zeros
    Copy-Item -LiteralPath $exact -Destination (Join-Path $root 'threshold-b.bin')
    $large = New-TestFile (Join-Path $root 'large-a.bin') (64MB + 1) -Zeros
    Copy-Item -LiteralPath $large -Destination (Join-Path $root 'large-b.bin')
    $different = Join-Path $root 'large-different-middle.bin'
    Copy-Item -LiteralPath $large -Destination $different
    $stream = [IO.File]::Open($different, 'Open', 'ReadWrite')
    try { $stream.Position = 3MB; $stream.WriteByte(0x71); $stream.Flush($true) }
    finally { $stream.Dispose() }
    $hashes = @(Get-ChildItem -LiteralPath $root -File | Get-FileHash | Sort-Object Path)
    $full = @($hashes | Group-Object Hash | Where-Object Count -GT 1 | ForEach-Object { $_.Group.Path } |
        Sort-Object)
    $runner = New-TestRunner @{ Options = @{ FileHashAlgorithm = 2; SampleLargeFiles = 1 } }
    foreach ($format in 'csv', 'json') {
        $rows = Invoke-ScanReport $runner @($root) "sampled-$format" -Kind Duplicates -Format $format
        Assert-Sequence @($rows.Name | Where-Object { $_ -ine $different } | Sort-Object) $full `
            'Sampled scanning retains every independently verified duplicate'
        foreach ($row in $rows) {
            Assert-Equal ([string]$row.'Sampled Hash').ToLowerInvariant() `
                $(if ([long]$row.'Logical Size' -gt 64MB) { 'true' } else { 'false' }) `
                'Only files above the sampling threshold carry the sampled-match warning'
        }
    }
    Set-TestSettings $runner @{ Options = @{ FileHashAlgorithm = 2; SampleLargeFiles = 0 } }
    $rows = Invoke-ScanReport $runner @($root) 'fully-verified' -Kind Duplicates
    Assert-Sequence @($rows.Name | Sort-Object) $full `
        'Whole-file verification rejects the apparent duplicate with different unsampled bytes'
    Assert-Equal @($rows | Where-Object { [string]$_.'Sampled Hash' -ine 'false' }).Count 0 `
        'Whole-file matches carry no sampled-match warning'
    Assert-Sequence @(Get-ChildItem -LiteralPath $root -File | Get-FileHash | Sort-Object Path | ForEach-Object Hash) `
        @($hashes.Hash) 'Both duplicate scan modes preserve every payload'
}

function Test-ReportSerialization {
    param($Context, $Case)
    $root = New-TestTree
    for ($index = 0; $index -lt 1025; ++$index) {
        $path = Join-Path $root ('unicode-雪-é-😀\branch-{0}\file-{1:d4},日本語.bin' -f ($index % 8), $index)
        New-TestFile $path ($index + 1) $index | Out-Null
    }
    $snapshot = Get-DiskSnapshot $root
    $fields = @('Name', 'Files', 'Folders', 'Logical Size', 'Physical Size', 'Attributes', 'Last Change',
        'WinDirStat Attributes', 'Index', 'ScanOutcome', 'ScanError')
    foreach ($owner in 0, 1) {
        $runner = New-TestRunner @{ FileTreeView = @{ ColumnVisibility = "1,1,1,1,1,1,1,1,1,1,$owner" } }
        $reports = @{}
        foreach ($format in 'csv', 'json') {
            $name = "serialization-$owner-$format"
            $rows = Invoke-ScanReport $runner @($root) $name -Format $format
            Assert-ScanSnapshot $rows $snapshot $root -Physical
            $reports[$format] = $rows
            $path = Join-Path $Context.Root "$name.$format"
            $bytes = [IO.File]::ReadAllBytes($path)
            Assert-True ($bytes.Length -gt 128KB) 'The report exercises multiple buffered writes'
            $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
            Assert-True ($text.Contains('雪-é-😀') -and $text.Contains(',日本語.bin')) `
                'UTF-8 reports preserve Unicode and comma-containing paths'
            if ($owner) {
                Assert-Equal @($rows | Where-Object { [string]::IsNullOrEmpty($_.Owner) }).Count 0 `
                    'Owner columns remain populated throughout a large report'
            }
            Invoke-ScanReport $runner @($root) "$name-repeat" -Format $format | Out-Null
            Assert-Equal (Get-FileHash -LiteralPath (Join-Path $Context.Root "$name-repeat.$format")).Hash `
                (Get-FileHash -LiteralPath $path).Hash 'Repeated exports preserve every output byte'
        }
        $columns = if ($owner) { $fields + 'Owner' } else { $fields }
        Assert-Sequence (Get-ReportSignature $reports.csv $columns) (Get-ReportSignature $reports.json $columns) `
            'Large CSV and JSON exports preserve the same metadata, ordering-independent'
    }
}

function Test-ReportRoundTrip {
    param($Context, $Case)
    $root = New-TestTree
    $snapshot = Get-DiskSnapshot $root
    $runner = New-TestRunner
    $source = Invoke-ScanReport $runner @($root) 'saved' -Format $Case.Format
    Assert-ScanSnapshot $source $snapshot $root -Physical
    $sentinel = New-TestFile (Join-Path $root 'unscanned-after-export.txt') 7829
    [IO.File]::WriteAllBytes((Join-Path $root 'alpha\selected-a.bin'), [byte[]]::new(3))
    $app = Start-TestApp -Runner $runner -Arguments @('/loadfrom', (Join-Path $Context.Root "saved.$($Case.Format)"))
    $app.Roots = @($root)
    $loaded = Save-AppReport $app 'loaded' -Format $Case.Format
    $fields = @('Name', 'Files', 'Folders', 'Logical Size', 'Physical Size', 'Attributes', 'Last Change',
        'WinDirStat Attributes', 'Index', 'ScanOutcome', 'ScanError')
    Assert-Sequence (Get-ReportSignature $loaded $fields) (Get-ReportSignature $source $fields) `
        'Loading and re-exporting uses the saved model even when live files have changed'
    $otherFormat = if ($Case.Format -eq 'csv') { 'json' } else { 'csv' }
    $converted = Save-AppReport $app 'converted' -Format $otherFormat
    Assert-Sequence (Get-ReportSignature $converted $fields) (Get-ReportSignature $source $fields) `
        'Converting a loaded report preserves metadata across CSV and JSON'
    Assert-Equal @($loaded | Where-Object Name -IEQ $sentinel).Count 0 `
        'Loading a report does not scan newly created files'
    Invoke-AppCommand $app 'ID_REFRESH_ALL'
    Wait-AppIdle $app
    $refreshed = Save-AppReport $app 'refreshed'
    Assert-ScanSnapshot $refreshed (Get-DiskSnapshot $root) $root -Physical
}

function Test-QuietFailure {
    param($Context, $Case)
    $root = New-TestTree
    $runner = New-TestRunner
    $missing = Join-Path $Context.Root 'nonexistent'
    $output = Join-Path $Context.Root 'must-not-exist.csv'
    $invalid = @(
        @('/saveto', $output, $missing),
        @('/saveto', $output, (Join-Path $root 'alpha\selected-a.bin')),
        @('/saveto', (Join-Path $missing 'report.csv'), $root),
        @('/saveto', $output, '/savedupesto', (Join-Path $Context.Root 'also-missing.csv'), $root)
    )
    foreach ($arguments in $invalid) {
        $probe = Invoke-TestProcess $runner $arguments -Seconds 10
        Assert-Equal $probe.ExitCode 1 `
            'An invalid quiet invocation terminates with a normal error rather than a hidden dialog or crash'
        Assert-True (-not (Test-Path -LiteralPath $output)) `
            'A rejected quiet invocation does not leave a misleading output report'
    }
    $rows = Invoke-ScanReport $runner @($root) 'after-rejection'
    Assert-ScanSnapshot $rows (Get-DiskSnapshot $root) $root
}

function Test-MalformedReportType {
    param($Context, $Case)
    $root = New-TestTree
    $runner = New-TestRunner
    $source = Invoke-ScanReport $runner @($root) 'valid' -Format $Case.Format
    foreach ($type in '0x30000200', '0x30000204', '0x30000008', '0x30000010', '0x30000020') {
        $row = $source[0].PSObject.Copy()
        $row.'WinDirStat Attributes' = $type
        $row.Index = '0x0000000000000001'
        $drive = $source[0].PSObject.Copy()
        $drive.Name = 'V:\'
        $drive.'WinDirStat Attributes' = '0x20000002'
        $rows = @($row, $drive)
        $path = Join-Path $Context.Root "malformed-$type.$($Case.Format)"
        if ($Case.Format -eq 'json') {
            [IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $rows))
        } else { $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8 }
        $app = Start-TestApp -Runner $runner -Arguments @('/loadfrom', $path) -Hidden
        Assert-True (-not (Get-AppCommandState $app 'ID_REFRESH_ALL').Enabled) `
            'A report rejects pointer-backed nodes, mixed types, and children attached to leaf roots'
        Stop-TestApp $app
    }
    $app = Start-TestApp -Runner $runner -Arguments @('/loadfrom', (Join-Path $Context.Root "valid.$($Case.Format)")) `
        -Hidden
    Assert-True (Get-AppCommandState $app 'ID_REFRESH_ALL').Enabled `
        'A valid saved model remains loadable after rejected reports'
    Assert-True ([TestDesktop]::Text($app.Window).Contains($root)) 'The valid report restores its scanned root'
    Assert-True (-not [TestDesktop]::IsWindowVisible($app.Window)) 'Report validation leaves the main window hidden'
}

function Test-MalformedLayoutSettings {
    param($Context, $Case)
    $root = New-TestTree
    $snapshot = Get-DiskSnapshot $root
    $invalid = @('10,,20', '10x,20', '2147483648', '-2147483649')
    for ($index = 0; $index -lt $invalid.Count; ++$index) {
        $value = $invalid[$index]
        $runner = New-TestRunner @{
            FileTreeView = @{ ColumnWidths = $value; ColumnOrder = $value; ColumnVisibility = $value }
            TreeMapView = @{ TreeMapCustomPreset = $value }
        }
        $app = Start-TestApp @($root) -Runner $runner
        Get-AppList $app -AllFiles | Out-Null
        Assert-True ([TestDesktop]::Message($app.TreeList, 0x101D).ToInt32() -gt 0) `
            'Malformed column settings recover to a visible name column'
        Assert-GraphRendered $app | Out-Null
        Assert-ScanSnapshot (Save-AppReport $app "malformed-layout-$index") $snapshot $root -Physical
        Stop-TestApp $app
    }
}

function Test-PermissionExport {
    param($Context, $Case)
    $root = New-TestTree
    $explicit = Join-Path $root 'explicit'
    $inherited = Join-Path $explicit 'inherited'
    [IO.Directory]::CreateDirectory($inherited) | Out-Null
    $acl = Get-Acl -LiteralPath $explicit
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-7')
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $explicit -AclObject $acl
    $runner = New-TestRunner
    $csv = Invoke-ScanReport $runner @($root) 'permissions-csv' -Kind Permissions
    $json = Invoke-ScanReport $runner @($root) 'permissions-json' -Kind Permissions -Format json
    $fields = @('Name', 'Account', 'Access', 'Rights', 'Applies To', 'Inherited', 'Access Mask')
    Assert-Sequence (Get-ReportSignature $csv $fields) (Get-ReportSignature $json $fields) `
        'CSV and JSON describe the same real ACLs and inheritance scopes'
    Assert-True (@($csv | Where-Object Name -IEQ $explicit).Count -gt 0) 'An explicit child ACL is exported'
    Assert-Equal @($csv | Where-Object Name -IEQ $inherited).Count 0 `
        'Inherited-only descendants do not duplicate parent ACL entries'
    $expectedAccount = $sid.Translate([Security.Principal.NTAccount]).Value
    Assert-True (@($csv | Where-Object { $_.Name -ieq $explicit -and $_.Account -ieq $expectedAccount }).Count -gt 0) `
        'The exported account resolves the SID actually applied to the fixture'
    $entry = @($csv | Where-Object { $_.Name -ieq $explicit -and $_.Account -ieq $expectedAccount })[0]
    Assert-Equal ([Convert]::ToUInt32($entry.'Access Mask', 16)) ([uint32]$rule.FileSystemRights) `
        'The permission export preserves the access mask applied to the directory'
    Assert-Equal $entry.Access 'Allow' 'The permission export preserves the applied access type'
}

function Assert-SameBytes {
    param([byte[]] $Left, [byte[]] $Right, [string] $Message)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        Assert-Equal ([BitConverter]::ToString($sha.ComputeHash($Left))) ([BitConverter]::ToString($sha.ComputeHash($Right))) $Message
    } finally { $sha.Dispose() }
}

$script:ZipFields = @('Name', 'Files', 'Folders', 'Logical Size', 'Physical Size', 'Attributes', 'Last Change',
    'WinDirStat Attributes', 'Index', 'ScanOutcome', 'ScanError')

function Test-ZipByteMatch {
    param($Context, $Case)
    $root = New-TestTree
    $runner = New-TestRunner
    $plainFormat = if ($Case.Format -eq 'json.zip') { 'json' } else { 'csv' }
    Invoke-ScanReport $runner @($root) 'plain' -Format $plainFormat -Kind $Case.Kind | Out-Null
    Invoke-ScanReport $runner @($root) 'zipped' -Format $Case.Format -Kind $Case.Kind | Out-Null
    $entry = Read-ZipReportEntry (Join-Path $Context.Root "zipped.$($Case.Format)")
    $inner = if ($Case.Format -eq 'json.zip') { '.json' } else { '.csv' }
    Assert-Equal $entry.Name "zipped$inner" "The $($Case.Kind) $($Case.Format) entry is named from the leaf"
    Assert-SameBytes ([IO.File]::ReadAllBytes((Join-Path $Context.Root "plain.$plainFormat"))) $entry.Bytes `
        "The $($Case.Kind) $($Case.Format) entry matches the plain export"
}

function Test-ZipRoundTrip {
    param($Context, $Case)
    $root = New-TestTree
    $runner = New-TestRunner
    $plainFormat = if ($Case.Format -eq 'json.zip') { 'json' } else { 'csv' }
    Invoke-ScanReport $runner @($root) 'plain' -Format $plainFormat | Out-Null
    Invoke-ScanReport $runner @($root) 'zipped' -Format $Case.Format | Out-Null
    $plain = Start-TestApp -Runner $runner -Arguments @('/loadfrom', (Join-Path $Context.Root "plain.$plainFormat"))
    $fromPlain = Save-AppReport $plain 'from-plain'
    Stop-TestApp $plain
    $zip = Start-TestApp -Runner $runner -Arguments @('/loadfrom', (Join-Path $Context.Root "zipped.$($Case.Format)"))
    $fromZip = Save-AppReport $zip 'from-zip'
    Stop-TestApp $zip
    Assert-Sequence (Get-ReportSignature $fromZip $script:ZipFields) (Get-ReportSignature $fromPlain $script:ZipFields) `
        "A $($Case.Format) load matches the plain load"
}

function New-ZipArchive {
    param([string] $Path, [System.Collections.IDictionary] $Entries)
    $archive = [IO.Compression.ZipFile]::Open($Path, 'Create')
    try {
        foreach ($name in $Entries.Keys) {
            $stream = $archive.CreateEntry($name).Open()
            try { $stream.Write($Entries[$name], 0, $Entries[$name].Length) } finally { $stream.Dispose() }
        }
    } finally { $archive.Dispose() }
}

function Test-ZipLoadEntries {
    param($Context, $Case)
    $root = New-TestTree
    $runner = New-TestRunner
    Invoke-ScanReport $runner @($root) 'source' | Out-Null
    Invoke-ScanReport $runner @($root) 'source' -Format json | Out-Null
    $csv = [IO.File]::ReadAllBytes((Join-Path $Context.Root 'source.csv'))
    $json = [IO.File]::ReadAllBytes((Join-Path $Context.Root 'source.json'))
    $valid = Join-Path $Context.Root 'valid.csv.zip'
    New-ZipArchive $valid ([ordered]@{ 'source.csv' = $csv })
    # A bare .zip name says nothing about the format, so the JSON entry has to be read by its own name
    New-ZipArchive (Join-Path $Context.Root 'inner.zip') ([ordered]@{ 'reports/' = [byte[]]::new(0); 'reports/source.json' = $json })
    New-ZipArchive (Join-Path $Context.Root 'multi.zip') ([ordered]@{ 'first.csv' = $csv; 'second.csv' = $csv })
    New-ZipArchive (Join-Path $Context.Root 'empty.zip') ([ordered]@{})
    $packed = [IO.File]::ReadAllBytes($valid)
    $packed[[int]($packed.Length / 2)] = $packed[[int]($packed.Length / 2)] -bxor 0xFF
    [IO.File]::WriteAllBytes((Join-Path $Context.Root 'corrupt.zip'), $packed)
    foreach ($case in @(
        @{ Name = 'valid.csv.zip'; Loads = $true }, @{ Name = 'inner.zip'; Loads = $true },
        @{ Name = 'multi.zip'; Loads = $false }, @{ Name = 'empty.zip'; Loads = $false },
        @{ Name = 'corrupt.zip'; Loads = $false })) {
        $app = Start-TestApp -Runner $runner -Arguments @('/loadfrom', (Join-Path $Context.Root $case.Name)) -Hidden
        Assert-True (-not $app.Process.HasExited) "A $($case.Name) archive does not crash"
        if ($case.Loads) {
            Wait-Until { (Get-AppCommandState $app 'ID_REFRESH_ALL').Enabled } "The $($case.Name) scan opens" | Out-Null
        }
        Assert-Equal (Get-AppCommandState $app 'ID_REFRESH_ALL').Enabled $case.Loads `
            "A $($case.Name) archive opens a scan only when it holds one report"
        Stop-TestApp $app
    }
}

function Test-ZipSaveFailure {
    param($Context, $Case)
    $root = New-TestTree
    $runner = New-TestRunner
    foreach ($leaf in 'scan.csv', 'scan.csv.zip') {
        $probe = Invoke-TestProcess $runner @('/saveto', (Join-Path $Context.Root "missing\$leaf"), $root)
        Assert-Equal $probe.ExitCode 1 "Saving $leaf into a missing folder fails"
    }
}

function Test-ZipEntryName {
    param($Context, $Case)
    $root = New-TestTree
    $runner = New-TestRunner
    foreach ($case in @(
        @{ Leaf = 'scan.zip'; Entry = 'scan.csv' },
        @{ Leaf = 'Scan.CSV.ZIP'; Entry = 'Scan.CSV' })) {
        $path = Join-Path $Context.Root $case.Leaf
        $probe = Invoke-TestProcess $runner @('/saveto', $path, $root)
        Assert-Equal $probe.ExitCode 0 "Saving $($case.Leaf) succeeds"
        Assert-Equal (Read-ZipReportEntry $path).Name $case.Entry "The $($case.Leaf) entry keeps its name"
    }
}

function Test-ZipTrailingSpace {
    param($Context, $Case)
    $root = New-TestTree
    $runner = New-TestRunner
    $source = Invoke-ScanReport $runner @($root) 'saved' -Format json
    $bytes = [IO.File]::ReadAllBytes((Join-Path $Context.Root 'saved.json'))
    $trailer = [Text.Encoding]::ASCII.GetBytes((' ' * 70 + "`r`n") * 120)
    Assert-True ($trailer.Length -gt 4KB) 'The trailer is longer than one read from the zip entry'
    $padded = [byte[]]::new($bytes.Length + $trailer.Length)
    [Buffer]::BlockCopy($bytes, 0, $padded, 0, $bytes.Length)
    [Buffer]::BlockCopy($trailer, 0, $padded, $bytes.Length, $trailer.Length)
    $zip = Join-Path $Context.Root 'padded.json.zip'
    New-ZipArchive $zip ([ordered]@{ 'saved.json' = $padded })
    $app = Start-TestApp -Runner $runner -Arguments @('/loadfrom', $zip)
    $loaded = Save-AppReport $app 'loaded' -Format json
    Stop-TestApp $app
    Assert-Sequence (Get-ReportSignature $loaded $script:ZipFields) (Get-ReportSignature $source $script:ZipFields) `
        'Trailing whitespace after the JSON array does not reject the zip'
}

foreach ($algorithm in @(@{ Name = 'sha256'; Value = 2 }, @{ Name = 'xxhash'; Value = 5 })) {
    Register-Scenario "reports.duplicates.$($algorithm.Name)" `
        Reports 'Full-file duplicate verification across staged hashing' `
        Test-DuplicateContent -Tags Filesystem -Data @{ Algorithm = $algorithm.Value }
}
foreach ($mode in @(@{ Name = 'serial'; Threads = 1 }, @{ Name = 'parallel'; Threads = 8 })) {
    Register-Scenario "reports.duplicates.batch-boundaries.$($mode.Name)" Reports `
        'Duplicate hashing and scan totals across full and partial publication batches' `
        Test-DuplicateBatchBoundaries -Tags Filesystem,Race -Data @{ Threads = $mode.Threads }
}
Register-Scenario reports.duplicates.sampling Reports 'Sampled matches remain distinguishable from whole-file duplicates' `
    Test-SampledDuplicates -Tags Filesystem
Register-Scenario reports.serialization Reports 'Large Unicode reports preserve metadata, owners, and output bytes' `
    Test-ReportSerialization -Tags Filesystem
foreach ($format in 'csv', 'json') {
    Register-Scenario "reports.roundtrip.$format" Reports `
        'Saved models survive external changes and refresh to current disk state' `
        Test-ReportRoundTrip -Tags Desktop,Persistence,External -Requires Windows,Desktop -Data @{ Format = $format }
    Register-Scenario "reports.malformed-type.$format" Reports 'Reject pointer-backed nodes in external reports' `
        Test-MalformedReportType -Tags External -Data @{ Format = $format }
}
Register-Scenario reports.quiet-failure Reports `
    'Invalid external CLI requests terminate and leave the next scan usable' `
    Test-QuietFailure -Tags External
Register-Scenario reports.malformed-layout Reports 'Malformed persisted integer lists recover to usable defaults' `
    Test-MalformedLayoutSettings -Tags Desktop,Persistence,External -Requires Windows,Desktop
Register-Scenario reports.permissions Reports 'Real ACL inheritance agrees across CSV and JSON exports' `
    Test-PermissionExport -Tags Filesystem -Requires Windows,Ntfs
foreach ($kind in 'Scan', 'Duplicates', 'Permissions') {
    foreach ($format in 'csv.zip', 'json.zip') {
        Register-Scenario "reports.zip.$($kind.ToLowerInvariant()).$format" Reports `
            "A $kind $format export matches the plain report byte for byte" `
            Test-ZipByteMatch -Tags Filesystem -Data @{ Kind = $kind; Format = $format }
    }
}
foreach ($format in 'csv.zip', 'json.zip') {
    Register-Scenario "reports.roundtrip.$format" Reports `
        'A zipped scan load matches the plain load' `
        Test-ZipRoundTrip -Tags Desktop,Persistence,External -Requires Windows,Desktop -Data @{ Format = $format }
}
Register-Scenario reports.zip.load-entries Reports 'Only an archive holding one report loads, read by the entry name' `
    Test-ZipLoadEntries -Tags External
Register-Scenario reports.zip.save-failure Reports 'A zip save into a missing folder fails like a plain save' `
    Test-ZipSaveFailure -Tags Filesystem
Register-Scenario reports.zip.entry-name Reports 'A bare zip and a mixed-case name keep the entry name' `
    Test-ZipEntryName -Tags Filesystem
Register-Scenario reports.zip.trailing-space Reports 'Whitespace after a JSON array still loads from a zip' `
    Test-ZipTrailingSpace -Tags External -Requires Windows,Desktop
