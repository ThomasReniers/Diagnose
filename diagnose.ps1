#requires -Version 5.1
<##############################################################################
  DIAGNOSE v8 - one script, two environments

  Windows: collects read-only information about programs and services.
  Docker:  the same script turns JSON input into a readable report.

  Examples:
    diagnose "Firefox"
    diagnose -p "Firefox"
    diagnose --service "wuauserv"
    diagnose -p -o md "Firefox"
    diagnose --service -o json "Windows Update"

  -o requires one format: md, txt, or json. Reports go to Diagnose\reports.
  The diagnose container remains available but stops after each scan.
###############################################################################>

$ErrorActionPreference = 'Stop'

function Text($Value) {
    if ($null -eq $Value) { return '' }
    return [string]$Value
}
# No hard-coded product list. Matches start from the user's input and
# are expanded with real executable names from registry entries and shortcuts.
function Resolve-Target([string]$Query) {
    $q = $Query.Trim()
    $base = [System.IO.Path]::GetFileNameWithoutExtension($q)
    $terms = @($q)
    if ($q -match '(?i)\.exe$' -and $base) { $terms += $base }
    return [pscustomobject]@{ terms = @($terms | Select-Object -Unique); executables = @() }
}
function Matches-Query($Value, [string]$Search) {
    $v = Text $Value
    $q = $Search.Trim()
    if (-not $v -or -not $q) { return $false }
    # Very short strings only match complete words, not arbitrary fragments.
    if ($q.Length -le 3) {
        $pattern = '(?i)(?<![a-z0-9])' + [regex]::Escape($q) + '(?![a-z0-9])'
        return [regex]::IsMatch($v, $pattern)
    }
    return $v.IndexOf($q, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}
function Matches-Target($Value, $Target) {
    foreach ($term in @($Target.terms)) {
        if (Matches-Query $Value $term) { return $true }
    }
    return $false
}
function Add-Target-Executable($Target, $Path) {
    $exe = [System.IO.Path]::GetFileName((Text $Path).Trim().Trim('"'))
    if ($exe -notmatch '(?i)\.exe$') { return }
    # Wrapper launchers are not useful product aliases.
    if ($exe -in @('cmd.exe','powershell.exe','pwsh.exe','rundll32.exe',
        'explorer.exe','msiexec.exe','wscript.exe','cscript.exe')) { return }
    if ($Target.executables -notcontains $exe) { $Target.executables = @($Target.executables) + @($exe) }
    if ($Target.terms -notcontains $exe) { $Target.terms = @($Target.terms) + @($exe) }
}

function Safe-Read([scriptblock]$Action) {
    try { return @(& $Action) } catch { return @() }
}
function Executable-FromCommand($CommandLine) {
    $value = [Environment]::ExpandEnvironmentVariables((Text $CommandLine).Trim())
    if ($value -match '^\s*"([^"]+\.(?:exe|sys))"') { return $Matches[1] }
    if ($value -match '^\s*(.+?\.(?:exe|sys))(?:\s|,|$)') { return $Matches[1] }
    return ''
}
function Path-Status($Path) {
    if ([string]::IsNullOrWhiteSpace((Text $Path))) { return 'unknown' }
    try {
        if (Test-Path -LiteralPath $Path -ErrorAction Stop) { return 'present' }
        return 'missing'
    } catch { return 'unknown' }
}
function Registry-Children($Path) {
    return @(Safe-Read { Get-ChildItem -LiteralPath $Path -ErrorAction Stop })
}

function Get-WindowsReport([string]$Query, [string]$Scope) {
    $target = Resolve-Target $Query
    $programs = @(); $applications = @(); $packages = @()
    $services = @(); $processes = @(); $registry = @()
    $folders = @(); $shortcuts = @(); $scanErrors = @()
    $isElevated = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}

    if ($Scope -ne 'service') {
        # The Start Menu maps visible names to EXE names without a product alias list.
        # We resolve only shortcuts whose names match the user query.
        $startRoots = @(
            (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'),
            (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs')
        )
        $shortcutShell = $null
        try { $shortcutShell = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch {
            $scanErrors += 'Start menu shortcuts could not be inspected (COM unavailable).'
        }
        if ($null -ne $shortcutShell) {
            foreach ($root in @($startRoots | Select-Object -Unique)) {
                if (-not (Test-Path -LiteralPath $root -PathType Container -ErrorAction SilentlyContinue)) { continue }
                try {
                    $links = @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.lnk' -ErrorAction Stop | Select-Object -First 4000)
                    foreach ($link in $links) {
                        if (-not (Matches-Target $link.BaseName $target)) { continue }
                        try {
                            $lnk = $shortcutShell.CreateShortcut($link.FullName)
                            $dest = [Environment]::ExpandEnvironmentVariables((Text $lnk.TargetPath))
                            if (-not $dest) { continue }
                            $shortcuts += [pscustomobject]@{
                                name = $link.BaseName; path = $dest
                                status = Path-Status $dest; shortcut = $link.FullName
                            }
                            Add-Target-Executable $target $dest
                            if ($dest -match '(?i)\.exe$' -and
                                [System.IO.Path]::GetFileName($dest) -notin @('cmd.exe','powershell.exe','pwsh.exe',
                                    'rundll32.exe','explorer.exe','msiexec.exe','wscript.exe','cscript.exe')) {
                                $applications += [pscustomobject]@{
                                    name = [System.IO.Path]::GetFileName($dest); path = $dest
                                    status = Path-Status $dest; source = 'Start menu shortcut'
                                }
                            }
                        } catch {}
                    }
                } catch { $scanErrors += 'Some Start menu folders could not be accessed.' }
            }
        }

        # Standard uninstall keys. An uninstaller is NOT the main application EXE.
        $uninstallRoots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        )
        foreach ($root in $uninstallRoots) {
            foreach ($key in @(Registry-Children $root)) {
                try {
                    $item = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                    if (-not (Matches-Target $item.DisplayName $target)) { continue }
                    $folder = [Environment]::ExpandEnvironmentVariables((Text $item.InstallLocation).Trim().Trim('"'))
                    $iconFile = Executable-FromCommand $item.DisplayIcon
                    if ($iconFile) { Add-Target-Executable $target $iconFile }
                    $programs += [pscustomobject]@{
                        name = Text $item.DisplayName
                        version = Text $item.DisplayVersion
                        publisher = Text $item.Publisher
                        folder = $folder
                        folder_status = Path-Status $folder
                        executable = $iconFile
                        exe_status = Path-Status $iconFile
                        registry_key = Text $key.Name
                    }
                } catch {}
            }
        }

        # App Paths entries are another generic catalog of executable names.
        foreach ($root in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'
        )) {
            foreach ($key in @(Registry-Children $root)) {
                if (-not (Matches-Target $key.PSChildName $target)) { continue }
                try {
                    $exePath = (Text $key.GetValue('')).Trim().Trim('"')
                    if (-not $exePath) {
                        $base = Text $key.GetValue('Path')
                        if ($base) { $exePath = Join-Path $base $key.PSChildName }
                    }
                    $exePath = [Environment]::ExpandEnvironmentVariables($exePath)
                    if ($exePath) { Add-Target-Executable $target $exePath }
                    $applications += [pscustomobject]@{
                        name = Text $key.PSChildName; path = $exePath
                        status = Path-Status $exePath; source = 'App Paths registry'
                    }
                } catch {}
            }
        }

        # A command available through PATH may be installed without an uninstall entry.
        foreach ($cmdName in @($Query, ([System.IO.Path]::GetFileNameWithoutExtension($Query) + '.exe')) | Select-Object -Unique) {
            if ($cmdName -notmatch '^[^\\/]+(?:\.exe)?$') { continue }
            try {
                foreach ($cmd in @(Get-Command -Name $cmdName -CommandType Application -ErrorAction Stop)) {
                    if (-not $cmd.Source) { continue }
                    Add-Target-Executable $target $cmd.Source
                    $applications += [pscustomobject]@{
                        name = Text $cmd.Name; path = Text $cmd.Source
                        status = Path-Status $cmd.Source; source = 'Windows PATH'
                    }
                }
            } catch {}
        }

        try {
            foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
                if ((Matches-Target $proc.Name $target) -or
                    (Matches-Target $proc.ExecutablePath $target)) {
                    $processes += [pscustomobject]@{
                        name = Text $proc.Name; pid = [int]$proc.ProcessId
                        path = Text $proc.ExecutablePath
                    }
                }
            }
        } catch { $scanErrors += 'Some running processes could not be inspected.' }

        if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
            try {
                foreach ($pkg in @(Get-AppxPackage -ErrorAction Stop)) {
                    if ((Matches-Target $pkg.Name $target) -or
                        (Matches-Target $pkg.PackageFamilyName $target)) {
                        $packages += [pscustomobject]@{
                            name = Text $pkg.Name; version = Text $pkg.Version
                            package = Text $pkg.PackageFullName
                        }
                    }
                }
            } catch { $scanErrors += 'Some Store/MSIX packages could not be inspected.' }
        }

        # Scan common program roots to bounded depth, rather than hard-coded
        # Firefox/Office paths. Not a full-disk scan, by design.
        $scanRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)},
            (Join-Path $env:LOCALAPPDATA 'Programs'),
            (Join-Path $env:USERPROFILE 'scoop\apps'))
        $queue = [System.Collections.Generic.Queue[object]]::new()
        foreach ($root in @($scanRoots | Where-Object { $_ } | Select-Object -Unique)) {
            if (Test-Path -LiteralPath $root -PathType Container -ErrorAction SilentlyContinue) {
                $queue.Enqueue([pscustomobject]@{ path = $root; level = 0; matchedParent = $false })
            }
        }
        $visited = 0; $fileHits = 0
        while ($queue.Count -gt 0 -and $visited -lt 2200 -and $fileHits -lt 60) {
            $entry = $queue.Dequeue()
            $visited++
            $dir = $entry.path
            $matchingFolder = [bool]$entry.matchedParent -or (Matches-Target ([System.IO.Path]::GetFileName($dir)) $target)
            if ($matchingFolder -and $entry.level -gt 0) {
                $folders += [pscustomobject]@{ path = $dir }
            }
            # Executables in an aptly named directory are only POSSIBLE matches;
            # we keep that source label separate from exact executable matches.
            try {
                foreach ($exe in @(Get-ChildItem -LiteralPath $dir -File -Filter '*.exe' -ErrorAction Stop)) {
                    $matchingFile = Matches-Target $exe.BaseName $target
                    if (-not $matchingFile -and -not $matchingFolder) { continue }
                    $applications += [pscustomobject]@{
                        name = $exe.Name; path = $exe.FullName; status = 'present'
                        source = $(if ($matchingFile) { 'Executable name on disk' } else { 'Possible executable in matching folder' })
                    }
                    $fileHits++
                    if ($fileHits -ge 60) { break }
                }
            } catch {}
            if ($entry.level -ge 3) { continue }
            try {
                foreach ($child in @(Get-ChildItem -LiteralPath $dir -Directory -ErrorAction Stop)) {
                    if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                    $queue.Enqueue([pscustomobject]@{
                        path = $child.FullName; level = $entry.level + 1
                        matchedParent = $matchingFolder
                    })
                }
            } catch {}
        }
        if ($queue.Count -gt 0) {
            $scanErrors += 'The bounded folder scan reached its limit; some locations were not inspected.'
        }
        $applications = @($applications | Sort-Object -Property path,source -Unique)
        $folders = @($folders | Sort-Object -Property path -Unique | Select-Object -First 80)

        # Registry traces are additional clues, not proof of installation.
        foreach ($root in @('HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node','HKCU:\SOFTWARE')) {
            foreach ($vendor in @(Registry-Children $root)) {
                if (Matches-Target $vendor.PSChildName $target) {
                    $registry += [pscustomobject]@{ path = Text $vendor.Name }
                }
                foreach ($key in @(Registry-Children $vendor.PSPath)) {
                    if (Matches-Target $key.PSChildName $target) {
                        $registry += [pscustomobject]@{ path = Text $key.Name }
                    }
                }
            }
        }
        foreach ($root in @('HKLM:\SOFTWARE\Clients\StartMenuInternet',
            'HKCU:\SOFTWARE\Clients\StartMenuInternet',
            'HKLM:\SOFTWARE\Classes\Applications',
            'HKCU:\SOFTWARE\Classes\Applications')) {
            foreach ($key in @(Registry-Children $root)) {
                if (Matches-Target $key.PSChildName $target) {
                    $registry += [pscustomobject]@{ path = Text $key.Name }
                }
            }
        }
        $registry = @($registry | Sort-Object -Property path -Unique | Select-Object -First 80)
    }

    if ($Scope -ne 'program') {
        try {
            foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
                if ((Matches-Target $svc.Name $target) -or
                    (Matches-Target $svc.DisplayName $target) -or
                    (Matches-Target $svc.PathName $target)) {
                    $exe = Executable-FromCommand $svc.PathName
                    $services += [pscustomobject]@{
                        name = Text $svc.Name
                        display_name = Text $svc.DisplayName
                        status = Text $svc.State
                        startup = Text $svc.StartMode
                        command = Text $svc.PathName
                        executable = $exe
                        exe_status = Path-Status $exe
                    }
                }
            }
        } catch { $scanErrors += 'Windows services could not be inspected.' }
    }
    $osName = ''
    try { $osName = Text (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
    return [pscustomobject]@{
        schema = 5
        query = $Query
        search_terms = @($target.terms | Select-Object -Unique)
        search_executables = @($target.executables | Select-Object -Unique)
        scope = $Scope
        computer = $env:COMPUTERNAME
        windows = $osName
        created = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        elevated = $isElevated
        programs = @($programs)
        applications = @($applications)
        shortcuts = @($shortcuts)
        packages = @($packages)
        services = @($services)
        processes = @($processes)
        registry = @($registry)
        folders = @($folders)
        errors = @($scanErrors)
    }
}

function Get-Interpretation($R) {
    $p = @($R.programs); $a = @($R.applications); $pkg = @($R.packages)
    $svc = @($R.services); $proc = @($R.processes)
    $links = @($R.shortcuts)
    $warnings = @()
    foreach ($item in $p) {
        if ($item.folder_status -eq 'missing') { $warnings += "Installation folder missing: $($item.name)" }
        if ($item.exe_status -eq 'missing') { $warnings += "Registered executable/icon target missing: $($item.name)" }
    }
    foreach ($item in $svc) {
        if ($item.exe_status -eq 'missing') { $warnings += "Service executable target missing: $($item.name)" }
    }
    foreach ($item in $a) {
        if ($item.status -eq 'missing') { $warnings += "Executable target missing ($($item.source)): $($item.name)" }
    }
    foreach ($item in $links) {
        if ($item.status -eq 'missing') { $warnings += "Start menu shortcut target missing: $($item.name)" }
    }
    # Only a real matching executable, package, process or service is strong evidence.
    # An arbitrary EXE in a matching directory is just a plausible match.
    $verified = (
        (@($a | Where-Object { $_.status -eq 'present' -and $_.source -ne 'Possible executable in matching folder' }).Count -gt 0) -or
        (@($p | Where-Object { $_.folder_status -eq 'present' -or $_.exe_status -eq 'present' }).Count -gt 0) -or
        ($pkg.Count -gt 0) -or ($proc.Count -gt 0) -or ($svc.Count -gt 0)
    )
    $registered = ($p.Count + $links.Count + @($a | Where-Object { $_.source -eq 'App Paths registry' }).Count) -gt 0
    $possible = (@($a | Where-Object { $_.source -eq 'Possible executable in matching folder' }).Count -gt 0)
    if ($verified) { $status = 'CONFIRMED MATCH'; $quality = 'Strong evidence'; $explanation = 'A matching file, process, package, or service was found. This does not guarantee a healthy installation.' }
    elseif ($registered) { $status = 'REGISTRATION FOUND'; $quality = 'Limited evidence'; $explanation = 'An installation record or shortcut was found, but a matching executable has not been verified.' }
    elseif ($possible) { $status = 'POSSIBLE MATCH'; $quality = 'Tentative evidence'; $explanation = 'An executable is located in a similarly named folder. Verify that it belongs to the requested application.' }
    elseif ((@($R.registry).Count + @($R.folders).Count) -gt 0) { $status = 'TRACES ONLY'; $quality = 'Weak evidence'; $explanation = 'Only similarly named registry keys or folders were found. These may be leftovers.' }
    else { $status = 'NO MATCH FOUND'; $quality = 'Not confirmed'; $explanation = 'No match was found in the inspected sources. This does NOT prove the software is absent.' }
    if ($warnings.Count -gt 0) { $status = 'WARNING: MISSING PATHS'; $explanation += ' Check the missing paths; do not delete anything based on this scan alone.' }
    return [pscustomobject]@{ status = $status; confidence = $quality; explanation = $explanation; warnings = @($warnings) }
}
# Issues are hypotheses based on observed system evidence, never a proof of corruption.
# Keep this independent of product names: same rules apply to every program/service.
function Get-DiagnosticIssues($R) {
    $issues = [System.Collections.Generic.List[object]]::new()
    $programs = @($R.programs)
    $apps = @($R.applications)
    $services = @($R.services)
    $links = @($R.shortcuts)

    $badServiceExecutables = @($services | Where-Object { $_.executable -and $_.exe_status -eq 'missing' })
    if ($badServiceExecutables.Count -gt 0) {
        $evidence = @($badServiceExecutables | Select-Object -First 4 | ForEach-Object {
            '{0}: {1}' -f $_.name, $_.executable
        })
        $issues.Add([pscustomobject]@{
            code = 'SERVICE_EXECUTABLE_MISSING'; severity = 'HIGH'
            title = 'A Windows service points to a missing executable'
            explanation = 'The service is registered but its configured executable is missing. It may fail to start. This can indicate an incomplete installation or an outdated service entry.'
            evidence = $evidence
            steps = @(
                'Check the executable path under INSTALLS. Confirm that the path is correct and the file is really missing.',
                'Verify which product owns this service and use the vendor-supplied repair option or installer.',
                'Retry the service only after addressing the missing target. Do not delete the service without further investigation.'
            )
        })
    }
    $badFolders = @($programs | Where-Object { $_.folder -and $_.folder_status -eq 'missing' })
    if ($badFolders.Count -gt 0) {
        $evidence = @($badFolders | Select-Object -First 4 | ForEach-Object {
            '{0}: {1}' -f $_.name, $_.folder
        })
        $issues.Add([pscustomobject]@{
            code = 'INSTALL_FOLDER_MISSING'; severity = 'MEDIUM'
            title = 'An installation record points to a missing folder'
            explanation = 'Windows still has an installation record pointing to a nonexistent folder. It may be a leftover entry; some installers do not populate InstallLocation accurately.'
            evidence = $evidence
            steps = @(
                'Check whether the application was installed in a different location.',
                'Check Windows Installed apps or Programs and Features for a current installation.',
                'Try the official repair option or full installer before considering registry changes.'
            )
        })
    }
    $badRegisteredExecutables = @($programs | Where-Object { $_.executable -and $_.exe_status -eq 'missing' })
    if ($badRegisteredExecutables.Count -gt 0) {
        $evidence = @($badRegisteredExecutables | Select-Object -First 4 | ForEach-Object {
            '{0}: {1}' -f $_.name, $_.executable
        })
        $issues.Add([pscustomobject]@{
            code = 'REGISTERED_EXECUTABLE_MISSING'; severity = 'MEDIUM'
            title = 'A registered executable or icon target is missing'
            explanation = 'A recorded file does not exist at the specified path. This field may refer to an icon, so it does not necessarily mean the main application is missing.'
            evidence = $evidence
            steps = @(
                'Check whether the main executable is present in the installation directory.',
                'If the application does not work, use its official repair option or installer.',
                'Do not edit registry paths until you know exactly what they are used for.'
            )
        })
    }
    $badLinks = @($links | Where-Object { $_.path -and $_.status -eq 'missing' })
    if ($badLinks.Count -gt 0) {
        $evidence = @($badLinks | Select-Object -First 4 | ForEach-Object {
            '{0}: {1}' -f $_.name, $_.path
        })
        $issues.Add([pscustomobject]@{
            code = 'BROKEN_SHORTCUT'; severity = 'LOW'
            title = 'A Start menu shortcut points to a missing file'
            explanation = 'The shortcut may be outdated or the application moved. This does not necessarily indicate a broken installation, but launching from this shortcut may fail.'
            evidence = $evidence
            steps = @(
                'Try launching the application from its installation directory or another shortcut.',
                'Use the vendor repair option or installer if the original target is no longer available.',
                'Remove an outdated shortcut only after confirming the correct target.'
            )
        })
    }
    $badApps = @($apps | Where-Object { $_.path -and $_.status -eq 'missing' -and $_.source -ne 'Start menu shortcut' })
    if ($badApps.Count -gt 0) {
        $evidence = @($badApps | Select-Object -First 4 | ForEach-Object {
            '{0} ({1}): {2}' -f $_.name, $_.source, $_.path
        })
        $issues.Add([pscustomobject]@{
            code = 'APP_PATH_MISSING'; severity = 'MEDIUM'
            title = 'A registered executable is missing'
            explanation = 'A Windows application entry points to a file that cannot be found. An incomplete uninstall or a changed installation directory is possible.'
            evidence = $evidence
            steps = @(
                'Compare the recorded path with the actual installation directory and check for another version.',
                'If there are problems, use the official repair option or perform a full reinstall.',
                'Do not remove App Paths registry entries unless you have verified they are obsolete.'
            )
        })
    }
    if ($issues.Count -eq 0 -and $R.interpretation.status -eq 'TRACES ONLY') {
        $issues.Add([pscustomobject]@{
            code = 'ONLY_TRACES'; severity = 'LOW'
            title = 'Only potential installation leftovers found'
            explanation = 'Similarly named folders or registry keys were found, but no installed application or service was confirmed. This may be normal after uninstalling or may belong to unrelated software.'
            evidence = @('No associated executable, package, process, or service was confirmed.')
            steps = @(
                'First verify whether the software was intentionally removed and whether user data must be preserved.',
                'If you want the application installed, try the official full installer.',
                'Only consider removing leftovers after backing up and verifying their origin.'
            )
        })
    }
    if ($issues.Count -eq 0 -and $R.interpretation.status -eq 'REGISTRATION FOUND') {
        $issues.Add([pscustomobject]@{
            code = 'UNVERIFIED_INSTALL'; severity = 'LOW'
            title = 'Registration found, installation not verified'
            explanation = 'Windows has an entry or shortcut, but the scanner could not confirm a matching executable. This might be a scan limitation.'
            evidence = @('An entry exists, but its executable has not been verified.')
            steps = @(
                'Check the installation path and the actual executable name.',
                'Try launching the program manually and note any error messages.',
                'Check Settings > Apps for repair options, or use the official installer.'
            )
        })
    }
    return @($issues.ToArray())
}

function Markdown-Code($value) {
    return ('`' + ((Text $value) -replace '[\r\n`]', ' ') + '`')
}

function Render-Markdown($R) {
    $l = [System.Collections.Generic.List[string]]::new()
    $l.Add('# Diagnose: ' + $R.query)
    $l.Add('')
    $l.Add('## SUMMARY')
    $l.Add('')
    $l.Add('**Status:** ' + $R.interpretation.status)
    $l.Add('')
    $l.Add('**Evidence level:** ' + $R.interpretation.confidence)
    $l.Add('')
    $l.Add('| Category | Count |'); $l.Add('| --- | ---: |')
    if ($R.scope -ne 'service') {
        $l.Add('| Installed programs | ' + @($R.programs).Count + ' |')
        $l.Add('| Executable references/files | ' + @($R.applications).Count + ' |')
        $l.Add('| Store/MSIX packages | ' + @($R.packages).Count + ' |')
        $l.Add('| Start menu shortcuts | ' + @($R.shortcuts).Count + ' |')
        $l.Add('| Matching folders | ' + @($R.folders).Count + ' |')
        $l.Add('| Running processes | ' + @($R.processes).Count + ' |')
        $l.Add('| Registry keys | ' + @($R.registry).Count + ' |')
    }
    if ($R.scope -ne 'program') { $l.Add('| Windows services | ' + @($R.services).Count + ' |') }
    $l.Add('| Potential issues | ' + @($R.issues).Count + ' |')
    $l.Add('')

    $l.Add('## SOURCE')
    $l.Add('')
    $l.Add('- **Computer:** ' + (Markdown-Code $R.computer))
    $l.Add('- **Operating system:** ' + $R.windows)
    $l.Add('- **Date:** ' + $R.created)
    $l.Add('- **Scan mode:** ' + $R.scope)
    $l.Add('- **Search query:** ' + (Markdown-Code $R.query))
    $l.Add('- **Expanded search terms:** ' + (@($R.search_terms) -join ', '))
    $l.Add('- **Run as administrator:** ' + $(if ($R.elevated) { 'yes' } else { 'no' }))
    $l.Add('')
    $l.Add('Data is collected from available Windows installation records, files, processes, services, shortcuts and registry entries. Docker renders the report.')
    $l.Add('')

    $l.Add('## 2. INSTALLS')
    $l.Add('')
    if ($R.scope -ne 'service') {
        $l.Add('### Registered installations')
        if (@($R.programs).Count -eq 0) { $l.Add('No matching installation records were found in the standard Windows locations.') }
        foreach ($x in @($R.programs)) {
            $l.Add('**' + $x.name + '**')
            $l.Add('- Version: ' + $x.version + ' | Publisher: ' + $x.publisher)
            $l.Add('- Installation folder: ' + (Markdown-Code $x.folder) + ' (' + $x.folder_status + ')')
            $l.Add('- Registered executable/icon: ' + (Markdown-Code $x.executable) + ' (' + $x.exe_status + ')')
            $l.Add('- Uninstall registry entry: ' + (Markdown-Code $x.registry_key))
            $l.Add('')
        }
        $l.Add('### Applications and executable files')
        if (@($R.applications).Count -eq 0) { $l.Add('No matching executables or executable references were found in the inspected locations.') }
        foreach ($x in @($R.applications)) {
            $l.Add('- **' + $x.name + '** (' + $x.status + '; ' + $x.source + '): ' + (Markdown-Code $x.path))
        }
        $l.Add('')
        $l.Add('### Start menu shortcuts')
        if (@($R.shortcuts).Count -eq 0) { $l.Add('No matching shortcuts were found.') }
        foreach ($x in @($R.shortcuts)) { $l.Add('- ' + $x.name + ': ' + (Markdown-Code $x.path) + ' (' + $x.status + ')') }
        $l.Add('')
        $l.Add('### Microsoft Store / MSIX')
        if (@($R.packages).Count -eq 0) { $l.Add('No matching packages for the current user.') }
        foreach ($x in @($R.packages)) { $l.Add('- ' + $x.name + ' (version ' + $x.version + ')') }
        $l.Add('')
        $l.Add('### Matching folders')
        if (@($R.folders).Count -eq 0) { $l.Add('No matching folders were found in the inspected default locations.') }
        foreach ($x in @($R.folders)) { $l.Add('- ' + (Markdown-Code $x.path)) }
        $l.Add('')
    }
    if ($R.scope -ne 'program') {
        $l.Add('### Windows services (registration and configuration)')
        if (@($R.services).Count -eq 0) { $l.Add('No matching Windows services were found.') }
        foreach ($x in @($R.services)) {
            $l.Add('**' + $x.display_name + '**')
            $l.Add('- Service name: ' + (Markdown-Code $x.name))
            $l.Add('- Status: ' + $x.status + ' (a stopped service may be normal)')
            $l.Add('- Startup mode: ' + $x.startup)
            $l.Add('- Executable: ' + (Markdown-Code $x.executable) + ' (' + $x.exe_status + ')')
            $l.Add('- Command line: ' + (Markdown-Code $x.command))
            $l.Add('')
        }
    }
    $l.Add('')

    $l.Add('## 3. PROCESSES')
    $l.Add('')
    if ($R.scope -eq 'service') {
        $l.Add('A separate process scan was not performed in service mode. See service status under **2. INSTALLS**.')
    } elseif (@($R.processes).Count -eq 0) {
        $l.Add('No matching running processes. This is normal if the application is closed.')
    } else {
        foreach ($x in @($R.processes)) { $l.Add('- ' + (Markdown-Code $x.name) + ' (PID ' + $x.pid + '): ' + (Markdown-Code $x.path)) }
    }
    $l.Add('')

    $l.Add('## 4. REGISTERS')
    $l.Add('')
    if ($R.scope -eq 'service') {
        $l.Add('A separate registry-key scan was not performed in service mode. See service registration under **2. INSTALLS**.')
    } elseif (@($R.registry).Count -eq 0) {
        $l.Add('No matching registry keys were found in the inspected locations.')
    } else {
        $l.Add('Registry keys found (' + @($R.registry).Count + '). Many may be normal file associations:')
        foreach ($x in @($R.registry)) { $l.Add('- ' + (Markdown-Code $x.path)) }
    }
    $l.Add('')

    $l.Add('## 5. CONCLUSION')
    $l.Add('')
    $l.Add('**' + $R.interpretation.status + '** - ' + $R.interpretation.confidence)
    $l.Add('')
    $l.Add($R.interpretation.explanation)
    foreach ($w in @($R.interpretation.warnings)) { $l.Add('- **Warning:** ' + $w) }
    $l.Add('')

    $l.Add('## 6. ISSUES')
    $l.Add('')
    if (@($R.issues).Count -eq 0) {
        $l.Add('**No clear issues detected** in the inspected information. This does not prove that all files and features work correctly.')
    } else {
        foreach ($x in @($R.issues)) {
            $l.Add('### [' + $x.severity + '] ' + $x.title)
            $l.Add($x.explanation)
            foreach ($e in @($x.evidence)) { $l.Add('- Evidence: ' + (Markdown-Code $e)) }
            $l.Add('')
        }
    }
    $l.Add('')

    $l.Add('## 7. TROUBLESHOOTING')
    $l.Add('')
    if (@($R.issues).Count -eq 0) {
        $l.Add('**No corrective action is indicated by this scan.**')
        $l.Add('')
        $l.Add('1. If there is a problem, check whether the application launches or the service behaves as expected.')
        $l.Add('2. Record the exact error and review Windows Event Viewer or the official repair options.')
        $l.Add('3. Do not delete files, registry entries or services based solely on their counts.')
    } else {
        $issueNumber = 0
        foreach ($x in @($R.issues)) {
            $issueNumber++
            $l.Add('### Issue ' + $issueNumber + ': ' + $x.title)
            $stepNumber = 0
            foreach ($step in @($x.steps)) {
                $stepNumber++
                $l.Add($stepNumber.ToString() + '. ' + $step)
            }
            $l.Add('')
        }
    }
    $l.Add('')

    $l.Add('## DISCLAIMER')
    $l.Add('')
    $l.Add('- The scan is read-only. No files, registry entries or services are changed.')
    $l.Add('- Finding a file or registration does not prove that the software is healthy. A missing path alone does not prove file corruption.')
    $l.Add('- A stopped process or inactive service is not inherently a problem.')
    $l.Add('- This is not a full-disk scan. Portable applications and protected data may be missed.')
    $l.Add('- Verify missing paths and use the official repair option when appropriate. Do not delete registry entries or services without further investigation.')
    $l.Add('- Reports may contain sensitive computer names, user names and local paths. Review them before sharing or publishing.')
    if (-not $R.elevated) { $l.Add('- The scan was not run as administrator; some information may be missing.') }
    foreach ($e in @($R.errors)) { $l.Add('- Scan limitation: ' + $e) }
    return ($l -join "`n")
}

function Render-Report($Report) {
    $line = ('=' * 69)
    $dash = ('-' * 69)
    $p = @($Report.programs); $s = @($Report.services)
    $r = @($Report.registry); $f = @($Report.folders)
    $proc = @($Report.processes); $apps = @($Report.applications)
    $packages = @($Report.packages); $links = @($Report.shortcuts)
    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add($line)
    $out.Add('  DIAGNOSE  |  ' + $Report.query)
    $out.Add($line)
    $out.Add('')

    $out.Add('SUMMARY')
    $out.Add($dash)
    $out.Add(('  Status                     : {0}' -f $Report.interpretation.status))
    $out.Add(('  Evidence level             : {0}' -f $Report.interpretation.confidence))
    if ($Report.scope -ne 'service') {
        $out.Add(('  Installed programs         : {0}' -f $p.Count))
        $out.Add(('  Executable references      : {0}' -f $apps.Count))
        $out.Add(('  Store/MSIX packages        : {0}' -f $packages.Count))
        $out.Add(('  Start menu shortcuts       : {0}' -f $links.Count))
        $out.Add(('  Matching folders           : {0}' -f $f.Count))
        $out.Add(('  Running processes          : {0}' -f $proc.Count))
        $out.Add(('  Registry keys              : {0}' -f $r.Count))
    }
    if ($Report.scope -ne 'program') { $out.Add(('  Windows services           : {0}' -f $s.Count)) }
    $out.Add(('  Potential issues           : {0}' -f @($Report.issues).Count))
    $out.Add('')

    $out.Add('SOURCE')
    $out.Add($dash)
    $out.Add(('  Computer         : {0}' -f $Report.computer))
    $out.Add(('  Windows          : {0}' -f $Report.windows))
    $out.Add(('  Date             : {0}' -f $Report.created))
    $out.Add(('  Scan mode        : {0}' -f $Report.scope))
    $out.Add(('  Search query     : {0}' -f $Report.query))
    $out.Add(('  Search terms     : {0}' -f (@($Report.search_terms) -join ', ')))
    $out.Add(('  Administrator    : {0}' -f $(if ($Report.elevated) { 'yes' } else { 'no' })))
    $out.Add('  Sources          : Windows installation records, files,')
    $out.Add('                     registry, processes, shortcuts and/or services.')
    $out.Add('')

    $out.Add('2. INSTALLS')
    $out.Add($dash)
    if ($Report.scope -ne 'service') {
        $out.Add(('  Registered installations ({0}):' -f $p.Count))
        if ($p.Count -eq 0) { $out.Add('    No matching installation record in the standard Windows locations.') }
        foreach ($item in $p) {
            $out.Add(('    Name        : {0}' -f $item.name))
            if ($item.version) { $out.Add(('    Version     : {0}' -f $item.version)) }
            if ($item.publisher) { $out.Add(('    Publisher   : {0}' -f $item.publisher)) }
            if ($item.folder) { $out.Add(('    Folder      : {0} [{1}]' -f $item.folder, $item.folder_status)) }
            else { $out.Add('    Folder      : not registered (not necessarily a problem)') }
            if ($item.executable) { $out.Add(('    Executable  : {0} [{1}]' -f $item.executable, $item.exe_status)) }
            $out.Add(('    Registry    : {0}' -f $item.registry_key))
            $out.Add('')
        }
        $out.Add(('  Applications and executables ({0}):' -f $apps.Count))
        if ($apps.Count -eq 0) { $out.Add('    No matching executable references or files found.') }
        foreach ($x in $apps) {
            $out.Add(('    {0} [{1}] - {2}' -f $x.name, $x.status, $x.source))
            $out.Add(('      {0}' -f $x.path))
        }
        $out.Add(('  Start menu shortcuts ({0}):' -f $links.Count))
        if ($links.Count -eq 0) { $out.Add('    No matching shortcuts found.') }
        foreach ($x in $links) { $out.Add(('    - {0} -> {1} [{2}]' -f $x.name, $x.path, $x.status)) }
        $out.Add(('  Store/MSIX packages ({0}, current user):' -f $packages.Count))
        if ($packages.Count -eq 0) { $out.Add('    No matching Store/MSIX packages found.') }
        foreach ($x in $packages) { $out.Add(('    - {0} (version {1})' -f $x.name, $x.version)) }
        $out.Add(('  Matching folders ({0}):' -f $f.Count))
        if ($f.Count -eq 0) { $out.Add('    No matching folders found in the inspected locations.') }
        foreach ($x in $f) { $out.Add(('    - {0}' -f $x.path)) }
    }
    if ($Report.scope -ne 'program') {
        $out.Add(('  Windows services ({0}, registration and configuration):' -f $s.Count))
        if ($s.Count -eq 0) { $out.Add('    No matching Windows services found.') }
        foreach ($item in $s) {
            $out.Add(('    Name        : {0} ({1})' -f $item.display_name, $item.name))
            $out.Add(('    Status      : {0} (stopped may be normal)' -f $item.status))
            $out.Add(('    Startup     : {0}' -f $item.startup))
            if ($item.executable) { $out.Add(('    Executable  : {0} [{1}]' -f $item.executable, $item.exe_status)) }
            if ($item.command) { $out.Add(('    Command     : {0}' -f $item.command)) }
            $out.Add('')
        }
    }
    $out.Add('')

    $out.Add('3. PROCESSES')
    $out.Add($dash)
    if ($Report.scope -eq 'service') {
        $out.Add('  No separate process scan in service mode.')
        $out.Add('  See service status under 2. INSTALLS.')
    } else {
        $out.Add(('  Running processes ({0}):' -f $proc.Count))
        if ($proc.Count -eq 0) { $out.Add('    No matching processes (normal if the application is closed).') }
        foreach ($item in $proc) { $out.Add(('    - {0} (PID {1}) {2}' -f $item.name, $item.pid, $item.path)) }
    }
    $out.Add('')

    $out.Add('4. REGISTERS')
    $out.Add($dash)
    if ($Report.scope -eq 'service') {
        $out.Add('  No separate registry key scan in service mode.')
        $out.Add('  See service registration under 2. INSTALLS.')
    } else {
        $out.Add(('  Registry keys ({0}):' -f $r.Count))
        if ($r.Count -eq 0) { $out.Add('    No matching keys found in the inspected locations.') }
        foreach ($item in $r) { $out.Add(('    - {0}' -f $item.path)) }
        if ($r.Count -gt 0) { $out.Add('  Note: normal file associations are not evidence of corruption.') }
    }
    $out.Add('')

    $out.Add('5. CONCLUSION')
    $out.Add($dash)
    $out.Add('  Status: ' + $Report.interpretation.status)
    $out.Add('  Evidence level: ' + $Report.interpretation.confidence)
    foreach ($x in @($Report.interpretation.warnings)) { $out.Add('  [WARNING] ' + $x) }
    $out.Add('  ' + $Report.interpretation.explanation)
    $out.Add('')

    $out.Add('6. ISSUES')
    $out.Add($dash)
    if (@($Report.issues).Count -eq 0) {
        $out.Add('  [OK] No clear issues detected in the inspected information.')
        $out.Add('  This does not prove that all files or features work correctly.')
    } else {
        $issueNumber = 0
        foreach ($issue in @($Report.issues)) {
            $issueNumber++
            $out.Add(('  {0}. [{1}] {2}' -f $issueNumber, $issue.severity, $issue.title))
            $out.Add('     ' + $issue.explanation)
            foreach ($evidence in @($issue.evidence)) { $out.Add('     Evidence: ' + $evidence) }
            $out.Add('')
        }
    }
    $out.Add('')

    $out.Add('7. TROUBLESHOOTING')
    $out.Add($dash)
    if (@($Report.issues).Count -eq 0) {
        $out.Add('  No corrective action is indicated by this scan.')
        $out.Add('  1. If it fails, test launching the application or the expected service behavior.')
        $out.Add('  2. Record the exact error and check Windows Event Viewer.')
        $out.Add('  3. Use official repair options; never remove entries based on counts alone.')
    } else {
        $issueNumber = 0
        foreach ($issue in @($Report.issues)) {
            $issueNumber++
            $out.Add(('  Issue {0}: {1}' -f $issueNumber, $issue.title))
            $stepNumber = 0
            foreach ($step in @($issue.steps)) {
                $stepNumber++
                $out.Add(('    {0}. {1}' -f $stepNumber, $step))
            }
            $out.Add('')
        }
    }
    $out.Add('')

    $out.Add('DISCLAIMER')
    $out.Add($dash)
    $out.Add('  - This read-only scan does not modify files, registry entries or services.')
    $out.Add('  - A matching file does not prove software works; a missing path is not')
    $out.Add('    proof of corruption.')
    $out.Add('  - An inactive process or stopped service is not automatically an issue.')
    $out.Add('  - This is not a full-disk scan; portable applications may be missed.')
    $out.Add('  - Do not delete registry keys or services without further verification.')
    $out.Add('  - Reports may contain computer/user names and local paths. Review before sharing.')
    if (-not $Report.elevated) { $out.Add('  - Not run as administrator; some information may be unavailable.') }
    foreach ($e in @($Report.errors)) { $out.Add('  - Scan limitation: ' + $e) }
    $out.Add($line)
    return ($out -join "`n")
}

# The Docker image uses the exact same file as the Windows scanner.
# The temporary JSON input is mounted read-only for one scan.
if ($args.Count -gt 0 -and $args[0] -eq '__render') {
    try {
        $inputPath = '/reports/.diagnose-input.json'
        if (-not (Test-Path -LiteralPath $inputPath)) {
            throw 'No input report found in /reports.'
        }
        $raw = [System.IO.File]::ReadAllText($inputPath, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) { throw 'The input report is empty.' }
        $report = $raw | ConvertFrom-Json -ErrorAction Stop
        $payload = [pscustomobject]@{ text = (Render-Report $report); markdown = (Render-Markdown $report) }
        [Console]::Out.WriteLine((ConvertTo-Json -InputObject $payload -Compress -Depth 10))
        exit 0
    } catch {
        [Console]::Error.WriteLine('Docker rendering error: ' + $_.Exception.Message)
        exit 1
    }
}

function Get-ManagedContainer {
    $result = (& docker container inspect 'diagnose' 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $result) { return $null }
    $items = @($result | ConvertFrom-Json -ErrorAction Stop)
    return $items[0]
}

function Ensure-DiagnoseContainer([string]$ReportsPath, [string]$ImageId) {
    $existing = Get-ManagedContainer
    if ($null -ne $existing) {
        # Never remove an unrelated container with the same name.
        if ($existing.Config.Labels.'diagnose.managed' -ne 'true') {
            throw 'A different container is already named diagnose. Rename it manually or change the container name in this tool.'
        }
        if ($existing.State.Running) {
            throw 'The Diagnose container is already running. Try again after it stops.'
        }
        $sameImage = ($existing.Image -eq $ImageId)
        $sameFolder = ($existing.Config.Labels.'diagnose.reports.path' -eq $ReportsPath)
        if ($sameImage -and $sameFolder) { return }
        # Recreate our managed container if the image or reports path has changed.
        & docker container rm diagnose | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'The existing Diagnose container could not be recreated.' }
    }

    $mount = 'type=bind,source=' + $ReportsPath + ',target=/reports,readonly'
    & docker create --name diagnose `
        --label 'diagnose.managed=true' `
        --label ('diagnose.reports.path=' + $ReportsPath) `
        --network none --read-only `
        --tmpfs '/tmp:rw,nosuid,size=16m' `
        --security-opt 'no-new-privileges:true' `
        --mount $mount `
        diagnose:latest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The Diagnose container could not be created.' }
}

function Show-Help {
@'
DIAGNOSE - Read-only Windows application and service diagnostics via Docker

Usage:
  diagnose "Firefox"               search programs and services; display in terminal
  diagnose -p "Firefox"            programs only
  diagnose --program "MyApp"       generic name-based search; no predefined product list
  diagnose -s "wuauserv"           Windows services only
  diagnose --service "Print Spooler"  search by display name
  diagnose -p -o md "Firefox"     terminal output plus Markdown report
  diagnose -p -o txt "MyApp"      terminal output plus plain-text report
  diagnose -s -o json "Spooler"   terminal output plus structured JSON report
  diagnose --help

Options:
  -p, --program      search programs only
  -s, --service      search Windows services only
  -o md|txt|json     save one report to Diagnose\reports (only these formats)
  -h, --help        show this help

The managed container remains in Docker Desktop (Stopped) after each scan.
The scanner does not modify applications, services, files, or registry keys.
'@ | Write-Output
}

try {
    if ($PSVersionTable.PSEdition -ne 'Core' -and $PSVersionTable.PSVersion.Major -lt 5) {
        throw 'PowerShell 5.1 or later is required.'
    }
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        throw 'The scan must run on the Windows host.'
    }

    $scope = 'all'
    $query = $null
    $format = ''
    for ($i = 0; $i -lt $args.Count; $i++) {
        $arg = Text $args[$i]
        $option = $arg.ToLowerInvariant()
        if ($option -in @('-h', '--help', '/?')) { Show-Help; exit 0 }
        if ($option -in @('-p', '--program')) {
            if ($scope -eq 'service') { throw 'Choose either -p or -s, not both.' }
            $scope = 'program'
            continue
        }
        if ($option -in @('-s', '--service')) {
            if ($scope -eq 'program') { throw 'Choose either -p or -s, not both.' }
            $scope = 'service'
            continue
        }
        if ($option -in @('-o', '--out')) {
            if ($format) { throw 'Use -o only once.' }
            if ($i + 1 -ge $args.Count) { throw 'After -o, specify md, txt or json.' }
            $i++
            $format = (Text $args[$i]).ToLowerInvariant()
            if ($format -notin @('md','txt','json')) { throw 'Invalid format. Only md, txt and json are supported.' }
            continue
        }
        if ($arg.StartsWith('-')) { throw "Unknown option: $arg. Use diagnose --help." }
        if ($null -ne $query) { throw 'Provide one search term; use quotes if it contains spaces.' }
        $query = $arg
    }
    if ([string]::IsNullOrWhiteSpace($query)) { Show-Help; exit 2 }
    if ($query.Length -gt 150) { throw 'Search query is too long (maximum 150 characters).' }
    if ($query.Trim().Length -lt 2) { throw 'Use at least two characters in the search query.' }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker CLI was not found. Start Docker Desktop and check your PATH.'
    }
    $osKind = (& docker info --format '{{.OSType}}' 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop is not running or cannot be reached.' }
    if ($osKind -ne 'linux') { throw 'Switch Docker Desktop to Linux containers.' }
    $imageId = (& docker image inspect 'diagnose:latest' --format '{{.Id}}' 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $imageId) {
        throw 'Image diagnose:latest was not found. First run this command in the Diagnose folder: docker build --no-cache -t diagnose:latest .'
    }
    Write-Host ("Collecting diagnostic data for: {0} ..." -f $query) -ForegroundColor DarkCyan
    $report = Get-WindowsReport -Query $query -Scope $scope
    $report | Add-Member -NotePropertyName interpretation -NotePropertyValue (Get-Interpretation $report)
    $report | Add-Member -NotePropertyName issues -NotePropertyValue @(Get-DiagnosticIssues $report)
    $json = ConvertTo-Json -InputObject $report -Depth 10 -Compress

    $reportsPath = Join-Path $PSScriptRoot 'reports'
    [void][System.IO.Directory]::CreateDirectory($reportsPath)
    $tempFile = Join-Path $reportsPath '.diagnose-input.json'

    # One reusable container and one input file: prevent concurrent scans.
    $lock = [System.Threading.Mutex]::new($false, 'Local\DiagnoseCliLock')
    $locked = $false
    try {
        try { $locked = $lock.WaitOne(30000) }
        catch [System.Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { throw 'Another scan is in progress. Try again after it finishes.' }

        [System.IO.File]::WriteAllText($tempFile, $json, [System.Text.UTF8Encoding]::new($false))
        Ensure-DiagnoseContainer -ReportsPath $reportsPath -ImageId $imageId

        # Reuse the same container. Without --rm, it remains visible as Stopped.
        $lines = @(& docker start --attach diagnose)
        if ($LASTEXITCODE -ne 0) { throw 'The Diagnose container could not be started successfully.' }
        $exitCode = (& docker container inspect diagnose --format '{{.State.ExitCode}}' | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $exitCode -ne '0') {
            throw 'Docker could not render the report. Check: docker logs diagnose'
        }
        $rawResult = $lines -join "`n"
        if ([string]::IsNullOrWhiteSpace($rawResult)) { throw 'Docker returned no output.' }
        try { $rendered = $rawResult | ConvertFrom-Json -ErrorAction Stop }
        catch { throw 'Docker returned an invalid report. Check: docker logs diagnose' }
        $plain = Text $rendered.text
        if (-not $plain) { throw 'No text report was received.' }
        Write-Output $plain
        if ($format) {
            $safe = ($query -replace '[^\p{L}\p{Nd}._-]', '-').Trim('-._')
            if (-not $safe) { $safe = 'query' }
            if ($safe.Length -gt 65) { $safe = $safe.Substring(0,65) }
            $name = '{0}-{1}-{2}.{3}' -f $safe, $scope, (Get-Date).ToString('yyyyMMdd-HHmmss-fff'), $format
            $outputPath = Join-Path $reportsPath $name
            switch ($format) {
                'txt' { $content = $plain.TrimEnd() + "`r`n" }
                'md' { $content = (Text $rendered.markdown).TrimEnd() + "`r`n" }
                'json' { $content = (ConvertTo-Json -InputObject $report -Depth 10) + "`r`n" }
            }
            [System.IO.File]::WriteAllText($outputPath, $content, [System.Text.UTF8Encoding]::new($false))
            Write-Host ("`nReport saved: {0}" -f $outputPath) -ForegroundColor Green
        }
    } finally {
        # Always remove temporary raw JSON input after a scan.
        if ($locked) {
            Remove-Item -LiteralPath $tempFile -ErrorAction SilentlyContinue
            [void]$lock.ReleaseMutex()
        }
        $lock.Dispose()
    }
    exit 0
} catch {
    [Console]::Error.WriteLine(('DIAGNOSE - ERROR: ' + $_.Exception.Message))
    exit 1
}
