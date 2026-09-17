<#
scripts/demo-run.ps1 — офлайн-демо стенда: ПАРА кампаний на моке
(vulnerable / protected), сравнение воронок шести стадий и ASR.

Запуск из корня репозитория: .\demo  (или scripts\demo-run.ps1 напрямую).
Параметры:
  -Python <путь>  python из venv; если задан — ЕДИНСТВЕННЫЙ кандидат, без перебора;
  -Open           открыть оба report.html в браузере (по умолчанию НЕ открывать).

Откуда берётся интерпретатор — упорядоченный список кандидатов. Кандидат годен
только если у него прошёл импорт memnotsafe.cli — входного модуля демо, с ним
вся цепочка зависимостей. Проба голым 'import memnotsafe' недостаточна и
измеренно провалилась: пакетный __init__ лёгкий, голый venv без yaml проходил
её и падал ModuleNotFoundError на первом же прогоне. Просто существующий файл
негоден по той же причине.
  1. путь из флага -Python;
  2. <корень checkout>\.venv-integration\Scripts\python.exe;
  3. <родитель корня>\agentic-red-teaming-main\.venv-integration\Scripts\python.exe
     (канонический checkout лежит вплотную к ворку agentic-red-teaming-main);
  3b. то же от ДЕДА корня — воркты живут в worktrees\, у них родитель корня это
      сам каталог worktrees, а venv ещё уровнем выше;
  4. python из PATH.
Ни один не годен — печатаем, что проверяли, подсказываем -Python, exit 1.

Пин W10: в PYTHONPATH кладётся src ЭТОГО дерева; до прогона печатается
memnotsafe.__file__ и ПРОВЕРЯЕТСЯ, что путь лежит внутри src этого checkout'а.
Указывает куда-то ещё — понятная ошибка и ненулевой выход, прогон не
продолжается. Унаследованный PYTHONPATH не затирается: src дописывается в
конец, и если чужой путь всё же выиграл разрешение, проверка __file__ ловит
это громко. Молча затереть чужой PYTHONPATH нельзя — это спрятало бы неверную
настройку окружения вместо того, чтобы её показать.

Без сети, без ключей: только mock-адаптер. Артефакты — в runs\demo-<UTC>/,
каталог runs/ в .gitignore. Ненулевой код возврата, если любой прогон упал.
#>

param(
    [string]$Python,
    [switch]$Open
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$SrcPath = Join-Path $RepoRoot "src"

# W10: демо обязано показывать код ЭТОГО дерева, а не первый memnotsafe из
# чужого site-packages. Унаследованный PYTHONPATH не затираем — дописываем src
# в конец; чужой путь, выигравший разрешение, ловится проверкой __file__ ниже.
if ($Env:PYTHONPATH) {
    $Env:PYTHONPATH = "$Env:PYTHONPATH;$SrcPath"
} else {
    $Env:PYTHONPATH = $SrcPath
}

function Test-MemnotsafeImport {
    param([string]$Exe)
    # 2>$null при $ErrorActionPreference="Stop" в PS 5.1 заворачивает stderr
    # нативного процесса в ErrorRecord и роняет скрипт; на время пробы
    # строгость выключается, годность решает только код возврата.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Exe -c "import memnotsafe.cli" 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Get-ExeOrNull {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($item -and -not $item.PSIsContainer) { return $Path }
    return $null
}

# --- кандидаты по порядку; годен тот, у кого прошёл импорт memnotsafe ---
$candidates = @()
if ($Python) {
    $candidates += [pscustomobject]@{ Label = "1: указан флагом -Python"; Exe = $Python }
} else {
    $candidates += [pscustomobject]@{ Label = "2: venv внутри checkout"; Exe = (Join-Path $RepoRoot ".venv-integration\Scripts\python.exe") }
    $parentDir = Split-Path -Parent $RepoRoot
    $candidates += [pscustomobject]@{ Label = "3: venv соседнего ворка agentic-red-teaming-main (родитель корня)"; Exe = (Join-Path $parentDir "agentic-red-teaming-main\.venv-integration\Scripts\python.exe") }
    $grandDir = Split-Path -Parent $parentDir
    if ($grandDir -and ($grandDir -ne $parentDir)) {
        $candidates += [pscustomobject]@{ Label = "3b: тот же venv от деда корня (воркт в worktrees\)"; Exe = (Join-Path $grandDir "agentic-red-teaming-main\.venv-integration\Scripts\python.exe") }
    }
    $pathCmd = Get-Command python -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pathCmd -and $pathCmd.Source) {
        $candidates += [pscustomobject]@{ Label = "4: python из PATH"; Exe = $pathCmd.Source }
    }
}

$selected = $null
foreach ($cand in $candidates) {
    $exe = Get-ExeOrNull -Path $cand.Exe
    if (-not $exe) {
        Write-Host ("  [{0}] файла нет: {1}" -f $cand.Label, $cand.Exe)
        continue
    }
    if (Test-MemnotsafeImport -Exe $exe) { $selected = $cand; break }
    Write-Host ("  [{0}] import memnotsafe.cli не прошёл: {1}" -f $cand.Label, $exe)
}
if (-not $selected) {
    Write-Host "ОШИБКА: не нашлось python, которым импортируется memnotsafe.cli. Проверяли:"
    foreach ($cand in $candidates) { Write-Host ("  [{0}] {1}" -f $cand.Label, $cand.Exe) }
    Write-Host "Укажите путь явно:"
    Write-Host "  .\demo -Python C:\полный\путь\к\.venv-integration\Scripts\python.exe"
    Write-Host "Как поднять venv: docs/integration-handoff/STANDING-RULES.md, раздел 6."
    exit 1
}
Write-Host ("ВЫБРАН PYTHON: {0} (кандидат: {1})" -f $selected.Exe, $selected.Label)

Write-Host "== код стенда (пин W10) =="
$prev = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $pinOutput = @(& $selected.Exe -c "import memnotsafe; print(memnotsafe.__file__)" 2>$null)
    $pinRc = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $prev
}
if ($pinRc -ne 0 -or $pinOutput.Count -eq 0) {
    Write-Host "ОШИБКА: memnotsafe не импортируется выбранным python (PYTHONPATH=$Env:PYTHONPATH)."
    exit 1
}
$importedFile = ([string]$pinOutput[-1]).Trim()
Write-Host ("memnotsafe.__file__ = {0}" -f $importedFile)
$normFile = $importedFile -replace "/", "\"
$normSrc = $SrcPath -replace "/", "\"
if (-not ($normFile -like ($normSrc + "\*"))) {
    Write-Host "ОШИБКА (пин W10): memnotsafe импортировался не из src этого дерева:"
    Write-Host ("  должно лежать внутри: {0}" -f $normSrc)
    Write-Host ("  импортировалось:      {0}" -f $importedFile)
    Write-Host "Прогон не продолжается: демо не запускает чужой код. Текущий PYTHONPATH:"
    Write-Host ("  PYTHONPATH={0}" -f $Env:PYTHONPATH)
    exit 1
}

$Python = $selected.Exe

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
