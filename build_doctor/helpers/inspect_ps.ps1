$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$raw = [Console]::In.ReadToEnd().Trim()
$req = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw)) | ConvertFrom-Json
$L = 'System.Management.Automation.Language'
$arch = if ([IntPtr]::Size -eq 4) { 'x86' } else { 'x64' }
try { $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant() } catch { }
$out = [ordered]@{
    ps_version = $PSVersionTable.PSVersion.ToString()
    edition = [string]$PSVersionTable.PSEdition
    process_arch = $arch
    language_mode = $ExecutionContext.SessionState.LanguageMode.ToString()
}
function Get-Const($n) {
    $dyn = [ordered]@{ dynamic = $true }
    if ($n -is "$L.PipelineAst") {
        if ($n.PipelineElements.Count -eq 1) { return Get-Const $n.PipelineElements[0] }
        return $dyn
    }
    if ($n -is "$L.CommandExpressionAst") { return Get-Const $n.Expression }
    if ($n -is "$L.StringConstantExpressionAst") { return $n.Value }
    if ($n -is "$L.ConstantExpressionAst") { return $n.Value }
    if ($n -is "$L.ArrayLiteralAst") {
        $items = New-Object System.Collections.ArrayList
        foreach ($e in $n.Elements) { [void]$items.Add((Get-Const $e)) }
        return , $items
    }
    if ($n -is "$L.HashtableAst") {
        $h = [ordered]@{}
        foreach ($kv in $n.KeyValuePairs) {
            if ($kv.Item1 -is "$L.StringConstantExpressionAst") { $h[$kv.Item1.Value] = Get-Const $kv.Item2 }
        }
        return $h
    }
    return $dyn
}
if ($req.mode -eq 'parse') {
    $tokens = $null
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($req.path, [ref]$tokens, [ref]$errs)
    $out.parse_errors = @($errs | ForEach-Object {
            [ordered]@{ message = $_.Message; id = $_.ErrorId; line = $_.Extent.StartLineNumber; column = $_.Extent.StartColumnNumber }
        })
    $r = $ast.ScriptRequirements
    if ($r) {
        $out.requires = [ordered]@{
            version = if ($r.RequiredPSVersion) { $r.RequiredPSVersion.ToString() } else { $null }
            editions = @($r.RequiredPSEditions)
            modules = @($r.RequiredModules | ForEach-Object { $_.Name })
            admin = [bool]$r.IsElevationRequired
        }
    }
    $refs = New-Object System.Collections.ArrayList
    $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $cmds) {
        $name = $c.GetCommandName()
        if (-not $name -or ($name -ne 'Import-Module' -and $name -ne 'Add-Type')) { continue }
        $els = $c.CommandElements
        $i = 1
        while ($i -lt $els.Count) {
            $e = $els[$i]
            $pname = ''
            $val = $e
            if ($e -is "$L.CommandParameterAst") {
                $pname = $e.ParameterName.ToLowerInvariant()
                $val = $e.Argument
                if (-not $val -and ($i + 1) -lt $els.Count -and $els[$i + 1] -isnot "$L.CommandParameterAst") {
                    $val = $els[$i + 1]
                    $i++
                }
            }
            $item = [ordered]@{ command = $name; param = $pname; line = $c.Extent.StartLineNumber; kind = 'dynamic' }
            if ($val -is "$L.StringConstantExpressionAst") {
                $item.kind = 'literal'
                if ($pname -like 'typedef*' -or $pname -like 'memberdef*' -or ($name -eq 'Add-Type' -and $pname -eq '')) {
                    $item.length = $val.Value.Length
                }
                else { $item.value = $val.Value }
            }
            if ($pname -ne 'verbose' -and $pname -ne 'force') { [void]$refs.Add($item) }
            $i++
        }
    }
    $out.references = @($refs)
    if ($req.path -like '*.psd1') {
        $h = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
        if ($h) {
            $keep = 'ModuleVersion', 'PowerShellVersion', 'PowerShellHostVersion', 'CompatiblePSEditions', 'ProcessorArchitecture', 'RequiredModules', 'RequiredAssemblies', 'RootModule', 'NestedModules', 'DotNetFrameworkVersion', 'CLRVersion'
            $m = [ordered]@{}
            foreach ($kv in $h.KeyValuePairs) {
                if ($kv.Item1 -is "$L.StringConstantExpressionAst" -and $keep -contains $kv.Item1.Value) {
                    $m[$kv.Item1.Value] = Get-Const $kv.Item2
                }
            }
            $out.manifest = $m
        }
    }
}
$out | ConvertTo-Json -Depth 8 -Compress
