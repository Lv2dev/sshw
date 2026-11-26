# Load in this session with: sshw completions powershell | Out-String | Invoke-Expression
# To persist, add that line to your PowerShell profile yourself.
Register-ArgumentCompleter -Native -CommandName sshw, sshw.exe -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $savedExitCode = $global:LASTEXITCODE
    try {
        $words = [System.Collections.Generic.List[string]]::new()
        $prefix = [string]$wordToComplete
        $prefixIsValue = $false
        $elements = @($commandAst.CommandElements)
        for ($i = 1; $i -lt $elements.Count; $i++) {
            $element = $elements[$i]
            if ($element.Extent.StartOffset -ge $cursorPosition) { break }
            # Only inspect literal AST values. Never evaluate expressions while completing.
            $literal = $element -is [System.Management.Automation.Language.StringConstantExpressionAst]
            $plainString = $element -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $element.NestedExpressions.Count -eq 0
            $parameter = $element -is [System.Management.Automation.Language.CommandParameterAst]
            if (!$literal -and !$plainString -and !$parameter) { return }
            if ($element.Extent.EndOffset -ge $cursorPosition) {
                if (($literal -or $plainString) -and $element.Extent.EndOffset -eq $cursorPosition) {
                    $prefix = [string]$element.Value
                    $prefixIsValue = $true
                }
                break
            }
            if ($literal -or $plainString) { $words.Add([string]$element.Value) }
            else { $words.Add($element.Extent.Text) }
        }
        # An unfinished quoted word can still be completed without evaluating it.
        if (!$prefixIsValue -and $prefix.StartsWith("'")) { $prefix = $prefix.Substring(1).TrimEnd("'").Replace("''", "'") }
        elseif (!$prefixIsValue -and $prefix.StartsWith('"')) { $prefix = $prefix.Substring(1).TrimEnd('"') }
        $request = @{ words = @($words.ToArray()); word = $prefix } | ConvertTo-Json -Compress -Depth 4
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($request))
        $executable = Get-Command -Name $commandAst.GetCommandName() -CommandType Application -ErrorAction Stop | Select-Object -First 1
        $PSNativeCommandUseErrorActionPreference = $false
        # The pipe carries only base64 ASCII. Keep the caller's native input
        # encoding out of the request (it can add a BOM or encode as UTF-16).
        $OutputEncoding = [System.Text.Encoding]::ASCII
        $result = $encoded | & $executable.Path completions powershell --query 2>$null
        if ($LASTEXITCODE -ne 0) { return }
        foreach ($item in ($result | ConvertFrom-Json)) {
            $value = [string]$item.value
            $completion = $value
            if ($value -notmatch '^[a-zA-Z0-9_./:=+-]+$') {
                $completion = "'" + $value.Replace("'", "''") + "'"
            }
            [System.Management.Automation.CompletionResult]::new(
                $completion, $value, [System.Management.Automation.CompletionResultType]$item.kind, [string]$item.description
            )
        }
    }
    catch { return }
    finally { $global:LASTEXITCODE = $savedExitCode }
}
