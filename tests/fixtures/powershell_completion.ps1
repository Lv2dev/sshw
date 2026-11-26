param([string]$Binary, [string]$TaskHome)
$ErrorActionPreference = 'Stop'
$env:PATH = (Split-Path -Parent $Binary) + [IO.Path]::PathSeparator + $env:PATH
if ($PSVersionTable.PSVersion.Major -eq 5) {
    # Exercise native output decoding under a Korean legacy console code page.
    [Console]::OutputEncoding = [Text.Encoding]::GetEncoding(949)
}
$registration = & $Binary completions powershell | Out-String
if ($LASTEXITCODE -ne 0) { throw 'script generation failed' }
& ([scriptblock]::Create($registration))
$quotedHome = "'" + $TaskHome.Replace("'", "''") + "'"
function Complete([string]$Tail, [string]$Expected) {
    $line = "sshw --home $quotedHome $Tail"
    $global:LASTEXITCODE = 37
    $matches = TabExpansion2 -inputScript $line -cursorColumn $line.Length
    if ($global:LASTEXITCODE -ne 37) { throw 'completion changed LASTEXITCODE' }
    $match = $matches.CompletionMatches | Where-Object ListItemText -EQ $Expected | Select-Object -First 1
    if (!$match) {
        $recentErrors = ($Error | Select-Object -First 2 | ForEach-Object { $_.Exception.Message }) -join ' | '
        throw "missing completion for [$Tail]: expected [$Expected], got [$($matches.CompletionMatches.ListItemText -join ', ')] (input code page $($OutputEncoding.CodePage), recent errors: $recentErrors)"
    }
    return @{ Line = $line; Match = $match; Result = $matches }
}
$null = Complete 'pa' 'password'
$originalEncoding = $OutputEncoding
try {
    foreach ($encoding in @([Text.UTF8Encoding]::new($true), [Text.Encoding]::Unicode)) {
        $OutputEncoding = $encoding
        $null = Complete 'pa' 'password'
        if ($OutputEncoding -ne $encoding) { throw 'completion changed the native input encoding' }
    }
}
finally { $OutputEncoding = $originalEncoding }
$null = Complete 'endp' 'endpoint'
$null = Complete 'endpoint pr' 'prod'
$null = Complete 'endpoint prod --po' '--port'
$null = Complete 'run --us' '--user'
$null = Complete 'account sh' 'show'
$null = Complete 'run pr' 'prod space'
$null = Complete 'run prod --user op' 'ops account'
$null = Complete 'run prod --user=op' '--user=ops account'
$null = Complete 'password prod --user op' 'ops account'
$null = Complete 'password prod --priv' '--privilege'
$null = Complete 'privilege set prod --account op' 'ops account'
$null = Complete 'account default prod op' 'ops account'
$null = Complete 'account remove prod deploy --switch-default op' 'ops account'
$null = Complete 'profile re' 'remove'
$null = Complete 'profile ren' 'rename'
$null = Complete 'doctor pr' 'prod'
$null = Complete 'doctor prod --user op' 'ops account'
$null = Complete 'get --int' '--into'
$null = Complete 'policy check-get --int' '--into'
$null = Complete 'test pr' 'prod'
$null = Complete 'test prod --user op' 'ops account'
$null = Complete 'put --prog' '--progress'
$null = Complete 'get --prog' '--progress'
$null = Complete 'default --cl' '--clear'
$null = Complete 'profile default --cl' '--clear'
$koreanName = ([char]0xAC1C).ToString() + [char]0xBC1C + ' ' + [char]0xC11C + [char]0xBC84
$null = Complete ('run ' + $koreanName.Substring(0, 1)) $koreanName
# PowerShell does not invoke native completers after its -- token. The data
# backend covers that grammar separately; this test exercises real callbacks.
$null = Complete "run 'prod s" 'prod space'
foreach ($name in @('prod space', "prod'quote", 'prod;$(throw ''must-not-run'')')) {
    $selected = Complete 'show pr' $name
    $text = $selected.Line.Substring(0, $selected.Result.ReplacementIndex) + $selected.Match.CompletionText + $selected.Line.Substring($selected.Result.ReplacementIndex + $selected.Result.ReplacementLength) + ' --json'
    $output = & ([scriptblock]::Create($text)) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $output.name -ne $name) { throw "quoted completion did not preserve the native argument: $name" }
}
# Completion of a destructive command must never execute that command.
$null = Complete 'remove pr' 'prod'
$null = Complete "remove prod --switch-default 'prod s" 'prod space'
$null = Complete 'remove prod --cl' '--clear-default'
$null = Complete 'profile remove old --cl' '--clear-default'

# Declared conflicts must not be offered, including the reverse direction.
foreach ($case in @(
    @('run prod uptime --stream ', '--json'),
    @('run prod uptime --json ', '--stream'),
    @('remove prod --clear-default ', '--switch-default'),
    @('remove prod --switch-default staging ', '--clear-default'),
    @('profile remove old --clear-default ', '--switch-default'),
    @('profile remove old --switch-default staging ', '--clear-default'),
    @('privilege set prod --no-password ', '--password-stdin'),
    @('privilege set prod --password-stdin ', '--no-password'),
    @('default prod ', '--clear'),
    @('profile default prod ', '--clear'),
    @('remove prod --clear-default ', '--switch-default=pr')
)) {
    $line = "sshw --home $quotedHome $($case[0])$($case[1])"
    $global:LASTEXITCODE = 37
    $matches = TabExpansion2 -inputScript $line -cursorColumn $line.Length
    if ($global:LASTEXITCODE -ne 37) { throw 'conflict completion changed LASTEXITCODE' }
    if ($matches.CompletionMatches.ListItemText -contains $case[1] -or
        $matches.CompletionMatches.ListItemText -contains '--switch-default=prod') {
        throw "conflicting option was completed: $line"
    }
}
$null = Complete 'run prod uptime --stream --y' '--yes'
$null = Complete 'remove prod --clear-default --j' '--json'

# A source/command named like another server must still use the actual default.
$ambiguityHome = Join-Path $TaskHome 'completion target cases'
$null = New-Item -ItemType Directory -Path $ambiguityHome -Force
$fixture = @{
    version = 2; default = 'prod'; credential_backend = 'session_only'
    servers = @{
        prod = @{ host = '192.0.2.10'; port = 22; default_user = 'deploy'; accounts = @{ deploy = @{ auth = @{ type = 'agent' } } } }
        report = @{ host = '192.0.2.11'; port = 22; default_user = 'auditor'; accounts = @{ auditor = @{ auth = @{ type = 'agent' } } } }
    }
} | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText((Join-Path $ambiguityHome 'servers.json'), $fixture, [Text.UTF8Encoding]::new($false))
$originalQuotedHome = $quotedHome
$quotedHome = "'" + $ambiguityHome.Replace("'", "''") + "'"
try {
    foreach ($tail in @(
        'run report --user d',
        'put report /destination --user d',
        'get report local --user d',
        'get report --into . --user d',
        'get --into=. report --user=d',
        'policy check report --user d',
        'policy check-put report /destination --user d',
        'policy check-get report local --user d',
        'policy check-get report --into=. --user d'
    )) {
        $expected = if ($tail.EndsWith('--user=d')) { '--user=deploy' } else { 'deploy' }
        $null = Complete $tail $expected
    }
    foreach ($tail in @(
        'run report id --user a',
        'put report source /destination --user a',
        'get report /source local --user a',
        'get report /source --into . --user a',
        'policy check report id --user a',
        'policy check-put report source /destination --user a',
        'policy check-get report /source local --user a',
        'policy check-get report /source --into . --user a'
    )) { $null = Complete $tail 'auditor' }
    $null = Complete 'policy check-put --at' '--atomic'
    $null = Complete 'policy check-get --int' '--into'
    foreach ($case in @(@('check-put', '--into'), @('check-get', '--atomic'))) {
        $line = "sshw --home $quotedHome policy $($case[0]) $($case[1])"
        $matches = TabExpansion2 -inputScript $line -cursorColumn $line.Length
        if ($matches.CompletionMatches.ListItemText -contains $case[1]) { throw "unsupported option was completed: $line" }
    }
    if (Test-Path (Join-Path $ambiguityHome 'audit.jsonl')) { throw 'completion wrote an audit log' }
    if (Test-Path (Join-Path $ambiguityHome '.sshw.lock')) { throw 'completion acquired a mutation lock' }
}
finally { $quotedHome = $originalQuotedHome }
$projectDir = Join-Path $TaskHome 'project completion'
$projectRoot = Join-Path $projectDir '.sshw'
$null = New-Item -ItemType Directory -Path $projectRoot -Force
[IO.File]::WriteAllText((Join-Path $projectRoot 'servers.json'), $fixture, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $projectRoot 'policy.json'), '{}', [Text.UTF8Encoding]::new($false))
$projectQuoted = "'" + $projectDir.Replace("'", "''") + "'"
foreach ($line in @(
    "sshw --project-dir $projectQuoted run pr",
    "sshw --project-dir=$projectQuoted run pr",
    "sshw --project-dir $projectQuoted run prod --user dep"
)) {
    $expected = if ($line.EndsWith('dep')) { 'deploy' } else { 'prod' }
    $global:LASTEXITCODE = 37
    $matches = TabExpansion2 -inputScript $line -cursorColumn $line.Length
    if ($global:LASTEXITCODE -ne 37 -or $matches.CompletionMatches.ListItemText -notcontains $expected) {
        throw "project completion failed: $line"
    }
}
Push-Location $projectDir
try {
    $line = 'sshw run pr'
    $matches = TabExpansion2 -inputScript $line -cursorColumn $line.Length
    if ($matches.CompletionMatches.ListItemText -notcontains 'prod') { throw 'cwd project completion failed' }
}
finally { Pop-Location }
if (Test-Path (Join-Path $projectRoot 'audit.jsonl')) { throw 'project completion wrote audit' }
if (Test-Path (Join-Path $projectRoot '.sshw.lock')) { throw 'project completion acquired a mutation lock' }
'PowerShell completion: PASS'
