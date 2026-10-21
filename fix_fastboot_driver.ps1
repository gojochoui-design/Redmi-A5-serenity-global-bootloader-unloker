# fix_fastboot_driver.ps1
# Arregla la deteccion de fastboot en Windows.
#
# Problema: el dispositivo fastboot (VID_18D1 & PID_D00D, "fastboot Gadget") queda atado a un
# driver WinUSB generico de libwdi/Zadig que NO registra el GUID de interfaz que fastboot.exe
# de Google busca. Resultado: "fastboot devices" sale vacio aunque Windows vea el movil.
#
# Solucion: anadir el GUID {F72FE0D4-CBCB-407d-8814-9ED673D0DD6B} (el que usa el driver
# "Android Bootloader Interface" de Google) a la clave DeviceInterfaceGUIDs del dispositivo
# y reiniciar el dispositivo USB. Reversible y sin riesgo.
#
# USO:  clic derecho -> Ejecutar con PowerShell  (se auto-eleva como administrador)

$guid = "{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}"
$hwid = 'VID_18D1&PID_D00D'

# --- auto-elevacion a administrador ---
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Relanzando como administrador (acepta el aviso de UAC)..."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# --- localizar el dispositivo fastboot ---
$dev = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match [regex]::Escape($hwid) } | Select-Object -First 1
if (-not $dev) {
    Write-Host "No hay ningun dispositivo fastboot ($hwid) conectado." -ForegroundColor Yellow
    Write-Host "Pon el movil en modo fastboot (apagado -> Vol- + Power) y vuelve a ejecutar."
    Read-Host "Pulsa ENTER para salir"
    exit
}
Write-Host "Dispositivo encontrado: $($dev.FriendlyName)" -ForegroundColor Green
Write-Host "  Instancia: $($dev.InstanceId)"

# --- anadir el GUID si falta ---
$devKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($dev.InstanceId)\Device Parameters"
$cur = (Get-ItemProperty -Path $devKey -Name DeviceInterfaceGUIDs -ErrorAction SilentlyContinue).DeviceInterfaceGUIDs
Write-Host "GUIDs actuales: $($cur -join ', ')"

if (@($cur) -notcontains $guid) {
    Set-ItemProperty -Path $devKey -Name DeviceInterfaceGUIDs -Value (@($cur) + $guid) -Type MultiString
    Write-Host "GUID $guid AGREGADO." -ForegroundColor Green
} else {
    Write-Host "El GUID ya estaba presente; no hay nada que cambiar."
}

# --- reiniciar el dispositivo USB ---
Write-Host "Reiniciando el dispositivo USB..."
$pn = pnputil /restart-device $dev.InstanceId 2>&1
Write-Output $pn

Write-Host ""
Write-Host "Listo. Comprueba ahora:  fastboot devices" -ForegroundColor Green
Write-Host "(debe listar el movil; si no, desconecta y reconecta el cable)"
Read-Host "Pulsa ENTER para salir"
