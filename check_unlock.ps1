# check_unlock.ps1 — Verifica el estado de desbloqueo del Redmi A5 4G (serenity)
# Uso:  powershell -ExecutionPolicy Bypass -File .\check_unlock.ps1

$ErrorActionPreference = "SilentlyContinue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== 1. Token de desbloqueo en miscdata ===" -ForegroundColor Cyan
$mdPath = Join-Path $here "miscdata-after.bin"
if (Test-Path $mdPath) {
    $md = [System.IO.File]::ReadAllBytes($mdPath)
    if ($md.Length -ge 8256) {
        $tok = $md[8192..8255]
        $nonzero = @($tok | Where-Object { $_ -ne 0 }).Count
        Write-Host ("Bytes no cero en el token @8192: {0} de 64" -f $nonzero)
        Write-Host (($tok | ForEach-Object { $_.ToString("X2") }) -join " ")
        if ($nonzero -eq 0) {
            Write-Host ">> Sin marcador: sigue bloqueado (pero la cadena de arranque esta restaurada)" -ForegroundColor Yellow
        } else {
            Write-Host ">> MARCADOR DE DESBLOQUEO PRESENTE (32 bytes + 2 hashes de 16)" -ForegroundColor Green
        }
    } else {
        Write-Host "miscdata-after.bin demasiado pequeno; repite la fase 5" -ForegroundColor Yellow
    }
} else {
    Write-Host "miscdata-after.bin no existe aqui (ejecuta antes la fase 5 del README)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== 2. Dispositivos USB (BootROM / fastboot) ===" -ForegroundColor Cyan
Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_1782|VID_18D1' } | ForEach-Object {
    Write-Host ("{0}  |  {1}" -f $_.FriendlyName, $_.InstanceId)
}
if (-not (Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_1782|VID_18D1' })) {
    Write-Host "(ninguno conectado)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== 3. Fastboot ===" -ForegroundColor Cyan
$fb = Join-Path $here "platform-tools\fastboot.exe"
if (-not (Test-Path $fb)) { $fb = "fastboot" }
$dev = (& $fb devices 2>&1) -join "`n"
Write-Output $dev
if ($dev -match "fastboot") {
    Write-Host "--- getvar unlocked ---"
    (& $fb getvar unlocked 2>&1) | Write-Output
    Write-Host "--- getvar current-slot ---"
    (& $fb getvar current-slot 2>&1) | Write-Output
    Write-Host "--- getvar anti ---"
    (& $fb getvar anti 2>&1) | Write-Output
} else {
    Write-Host "Pon el movil en fastboot para la comprobacion definitiva:" -ForegroundColor Yellow
    Write-Host "  apagado del todo -> mantener Vol- y pulsar Power -> conectar USB" -ForegroundColor Yellow
}

Write-Host ""
Read-Host "Pulsa ENTER para salir"
