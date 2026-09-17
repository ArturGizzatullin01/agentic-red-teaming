<#
scripts/demo-run.ps1 — офлайн-демо стенда: ПАРА кампаний на моке
(vulnerable / protected), сравнение воронок шести стадий и ASR.

Запуск из корня репозитория: .\demo  (или scripts\demo-run.ps1 напрямую).
Параметры:
  -Python <путь>  python из venv (по умолчанию
                  <корень>\agentic-red-teaming-main\.venv-integration\Scripts\python.exe);
  -Open           открыть оба report.html в браузере (по умолчанию НЕ открывать).

Без сети, без ключей: только mock-адаптер. Артефакты — в runs\demo-<UTC>/,
каталог runs/ в .gitignore. Ненулевой код возврата, если любой прогон упал.
#>

param(
    [string]$Python,
    [switch]$Open
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Python) {
    $Python = Join-Path $RepoRoot "agentic-red-teaming-main\.venv-integration\Scripts\python.exe"
}

if (-not (Test-Path $Python)) {
    Write-Host "ОШИБКА: python из venv не найден: $Python"
    Write-Host "Создайте venv (docs/integration-handoff/STANDING-RULES.md, раздел 6) или укажите путь:"
    Write-Host "  .\demo -Python C:\полный\путь\к\.venv-integration\Scripts\python.exe"
    exit 1
}

# W10: пин импорта — демо обязано показывать код ЭТОГО дерева, а не первый
# memnotsafe из чужого site-packages.
$SrcPath = Join-Path $RepoRoot "src"
if ($Env:PYTHONPATH) {
    $Env:PYTHONPATH = "$SrcPath;$Env:PYTHONPATH"
} else {
    $Env:PYTHONPATH = $SrcPath
}
Write-Host "== код стенда (пин W10) =="
& $Python -c "import memnotsafe; print('memnotsafe.__file__ =', memnotsafe.__file__)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ОШИБКА: memnotsafe не импортируется (PYTHONPATH=$Env:PYTHONPATH)."
    exit 1
}

$Stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$BaseDir = Join-Path $RepoRoot "runs\demo-$Stamp"

function Invoke-DemoCampaign {
    param([string]$Label, [string]$ScenarioName, [string]$OutDir)
    $scenario = Join-Path $RepoRoot ("scenarios\" + $ScenarioName)
    Write-Host ""
    Write-Host "== кампания: $Label ($ScenarioName, 5 повторов) =="
    $raw = & $Python -m memnotsafe.cli campaign --scenario $scenario --output $OutDir --json
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ОШИБКА: прогон $Label упал (код $LASTEXITCODE)."
        if ($raw) { $raw | ForEach-Object { Write-Host $_ } }
        exit $LASTEXITCODE
    }
    # stdout-JSON даёт пути артефактов; воронка/ASR лежат в report.json (metrics).
    $obj = ($raw -join "`n") | ConvertFrom-Json
    $reportJson = [string]$obj.artifacts[1]
    $metrics = (Get-Content -Raw -LiteralPath $reportJson | ConvertFrom-Json).metrics
    return [PSCustomObject]@{ Html = [string]$obj.artifacts[0]; Metrics = $metrics }
}

$vuln = Invoke-DemoCampaign "vulnerable" "tool_argument_hijack.yaml" (Join-Path $BaseDir "vulnerable")
$prot = Invoke-DemoCampaign "protected" "tool_argument_hijack_protected.yaml" (Join-Path $BaseDir "protected")

$stages = @("write", "persistence", "retrieval", "adoption", "tool", "external_effect")
Write-Host ""
Write-Host "== сравнение воронок (pass/fail/unknown на стадию, 5 повторов) =="
Write-Host ("{0,-16} {1,-14} {2:-14}" -f "stage", "vulnerable", "protected")
foreach ($s in $stages) {
    $fv = $vuln.Metrics.funnel.$s
    $fp = $prot.Metrics.funnel.$s
    Write-Host ("{0,-16} {1,-14} {2:-14}" -f $s,
        ("{0}/{1}/{2}" -f $fv.pass, $fv.fail, $fv.unknown),
        ("{0}/{1}/{2}" -f $fp.pass, $fp.fail, $fp.unknown))
}

Write-Host ""
$asrLine = "END-TO-END ASR: vulnerable {0:P0} ({1}/{2}) | protected {3:P0} ({4}/{5})" -f $vuln.Metrics.end_to_end_asr, $vuln.Metrics.successful, $vuln.Metrics.attempts, $prot.Metrics.end_to_end_asr, $prot.Metrics.successful, $prot.Metrics.attempts
Write-Host $asrLine

$diffStages = @()
foreach ($s in $stages) {
    $fv = $vuln.Metrics.funnel.$s
    $fp = $prot.Metrics.funnel.$s
    if (($fv.pass -ne $fp.pass) -or ($fv.fail -ne $fp.fail)) { $diffStages += $s }
}
if ($diffStages.Count -gt 0) {
    Write-Host ("различаются стадии: " + ($diffStages -join ", "))
} else {
    Write-Host "ВНИМАНИЕ: стадии воронки не различаются — защита на этом прогоне не видна."
}

Write-Host ""
Write-Host "== отчёты =="
Write-Host $vuln.Html
Write-Host $prot.Html
if ($Open) {
    Start-Process $vuln.Html
    Start-Process $prot.Html
}
Write-Host ""
Write-Host "артефакты прогона: $BaseDir (runs/ в .gitignore)"
exit 0
