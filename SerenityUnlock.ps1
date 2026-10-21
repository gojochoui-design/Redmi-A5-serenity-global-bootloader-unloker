# ============================================================================
#  SerenityUnlock.ps1
#  Desbloqueo del bootloader - Redmi A5 4G (serenity / Unisoc UMS9230E)
#  Interfaz gráfica para el flujo CVE-2022-38694 (BootROM/FDL)
#
#  Basado en:
#    - TomKing062/CVE-2022-38694_unlock_bootloader
#    - TomKing062/spreadtrum_flash (spd_dump)
#
#  AVISO: úsalo SOLO en un móvil que sea tuyo. El desbloqueo BORRA todos los
#  datos y puede dejar el terminal inservible si se interrumpe una escritura.
#
#  Uso: ejecuta SerenityUnlock.bat  (o este .ps1 con PowerShell)
# ============================================================================

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$here = Split-Path -Parent $PSCommandPath

# ---------------- auto-elevación a administrador ----------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and $env:SERENITY_AUTOTEST -ne "1") {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`""
    exit
}

# ---------------- requisitos ----------------
$required = @("spd_dump.exe","fdl1-dl.bin","fdl2-dl.bin","custom_exec_no_verify_65015f08.bin","fdl2-cboot.bin","misc-wipe.bin","gen_spl-unlock.exe","chsize.exe")
$missing  = @($required | Where-Object { -not (Test-Path (Join-Path $here $_)) })

# ---------------- estado global ----------------
$script:slot       = "a"
$script:logBox     = $null
$script:status     = $null
$script:buttons    = @()
$script:lastOutput = ""

# ---------------- utilidades de interfaz ----------------
function Log {
    param([string]$text)
    if ($script:logBox) {
        $script:logBox.AppendText($text + "`r`n")
        $script:logBox.SelectionStart = $script:logBox.TextLength
        $script:logBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function SetStatus {
    param([string]$text, $color = $null)
    if ($script:status) {
        $script:status.Text = $text
        if ($color) { $script:status.ForeColor = $color }
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function SetBusy {
    param([bool]$busy)
    foreach ($b in $script:buttons) { $b.Enabled = -not $busy }
    [System.Windows.Forms.Application]::DoEvents()
}

function Read-SharedFile {
    param([string]$path)
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs)
        $t  = $sr.ReadToEnd()
        $sr.Close()
        return $t
    } catch { return $null }
}

# ---------------- ejecutar un proceso con log en vivo ----------------
function Invoke-Exe {
    param([string]$exe, [string]$argLine)
    $outF = Join-Path $env:TEMP ("serenity_out_{0}.log" -f $PID)
    $errF = Join-Path $env:TEMP ("serenity_err_{0}.log" -f $PID)
    Remove-Item $outF, $errF -ErrorAction SilentlyContinue
    Log ""
    Log ("> " + (Split-Path -Leaf $exe) + " " + $argLine)
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argLine -WorkingDirectory $here -PassThru -WindowStyle Hidden -RedirectStandardOutput $outF -RedirectStandardError $errF
    } catch {
        Log ("ERROR al lanzar el proceso: " + $_.Exception.Message)
        return -1
    }
    $lastOut = 0; $lastErr = 0
    while (-not $p.HasExited) {
        Start-Sleep -Milliseconds 250
        [System.Windows.Forms.Application]::DoEvents()
        $t = Read-SharedFile $outF
        if ($t -and $t.Length -gt $lastOut) { $chunk = $t.Substring($lastOut); Log $chunk; $script:lastOutput += $chunk; $lastOut = $t.Length }
        $t = Read-SharedFile $errF
        if ($t -and $t.Length -gt $lastErr) { $chunk = $t.Substring($lastErr); Log $chunk; $lastErr = $t.Length }
    }
    $t = Read-SharedFile $outF
    if ($t -and $t.Length -gt $lastOut) { $chunk = $t.Substring($lastOut); Log $chunk; $script:lastOutput += $chunk }
    $t = Read-SharedFile $errF
    if ($t -and $t.Length -gt $lastErr) { Log $t.Substring($lastErr) }
    Remove-Item $outF, $errF -ErrorAction SilentlyContinue
    Log ("[terminado, exit code " + $p.ExitCode + "]")
    return $p.ExitCode
}

# ---------------- detección ----------------
function Get-BootROMDevice   { Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_1782' } | Select-Object -First 1 }
function Get-FastbootDevice  { Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_18D1' } | Select-Object -First 1 }

function Invoke-Detect {
    SetBusy $true
    SetStatus "Detectando dispositivos..."
    Log "=== Detección de dispositivos ==="
    $br = Get-BootROMDevice
    $fb = Get-FastbootDevice
    if ($br) { Log ("[OK] Modo BootROM/descarga: " + $br.FriendlyName + "  (" + $br.InstanceId + ")") }
    else     { Log "[--] No hay móvil en modo BootROM (VID_1782)" }
    if ($fb) { Log ("[OK] Modo fastboot: " + $fb.FriendlyName + "  (" + $fb.InstanceId + ")") }
    else     { Log "[--] No hay móvil en fastboot (VID_18D1)" }
    if (-not $br -and -not $fb) {
        Log "Conecta el móvil así:"
        Log "  - Modo BootROM/descarga: apagado -> mantener Vol- y conectar USB (la pantalla queda en negro)"
        Log "  - Modo fastboot:         apagado -> Vol- + Power hasta el logo"
        Log "REGLA IMPORTANTE: ejecuta primero el comando de cada fase y conecta el móvil DESPUÉS (espera 300 s)."
        SetStatus "No se detecta el móvil" ([System.Drawing.Color]::Firebrick)
    } else {
        SetStatus "Móvil detectado" ([System.Drawing.Color]::Green)
    }
    SetBusy $false
}

# ---------------- driver fastboot ----------------
function Invoke-DriverFix {
    SetBusy $true
    Log "=== Arreglo del driver fastboot (GUID de interfaz) ==="
    $guid = "{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}"
    $dev  = Get-FastbootDevice
    if (-not $dev) {
        Log "No hay ningún móvil en fastboot conectado (VID_18D1&PID_D00D)."
        Log "Ponlo en fastboot (Vol- + Power) y vuelve a intentarlo."
        SetStatus "Sin móvil en fastboot" ([System.Drawing.Color]::Firebrick)
        SetBusy $false
        return
    }
    Log ("Dispositivo: " + $dev.FriendlyName + "  (" + $dev.InstanceId + ")")
    $devKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\" + $dev.InstanceId + "\Device Parameters"
    $cur = (Get-ItemProperty -Path $devKey -Name DeviceInterfaceGUIDs -ErrorAction SilentlyContinue).DeviceInterfaceGUIDs
    Log ("GUIDs actuales: " + ($cur -join ", "))
    if (@($cur) -notcontains $guid) {
        Set-ItemProperty -Path $devKey -Name DeviceInterfaceGUIDs -Value (@($cur) + $guid) -Type MultiString
        Log ("GUID " + $guid + " agregado.")
    } else {
        Log "El GUID ya estaba presente; no hay nada que cambiar."
    }
    $null = Invoke-Exe "pnputil.exe" ("/restart-device `"" + $dev.InstanceId + "`"")
    Log "Hecho. Comprueba con el botón 'Detectar dispositivo' o con fastboot devices."
    SetStatus "Driver fastboot comprobado/arreglado" ([System.Drawing.Color]::Green)
    SetBusy $false
}

# ---------------- FASE 1: backup (solo lectura) ----------------
function Invoke-Phase1 {
    SetBusy $true
    SetStatus "Fase 1: copia de seguridad (solo lectura)..."
    Log "=== FASE 1: Backup (solo lectura) ==="
    Log "El comando queda escuchando 300 s: conecta el móvil en modo BootROM (apagado + Vol- + USB)."
    $script:lastOutput = ""
    $rc = Invoke-Exe (Join-Path $here "spd_dump.exe") "--wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec r splloader r uboot read_part miscdata 0 1048576 miscdata-baseline.bin reset"
    if (Test-Path (Join-Path $here "splloader.bin")) { Log "[OK] splloader.bin leído (256 KB en bruto)" }
    if (Test-Path (Join-Path $here "uboot.bin"))     { Log "[OK] uboot.bin leído" }
    if ($script:lastOutput -match 'Device is using slot (\w)') {
        $script:slot = $Matches[1]
        Log ("[OK] Slot activo detectado: " + $script:slot)
    }
    if ($rc -eq 0) { SetStatus "Fase 1 completada" ([System.Drawing.Color]::Green) }
    else           { SetStatus ("Fase 1 terminó con código " + $rc + " - revisa el log") ([System.Drawing.Color]::DarkOrange) }
    SetBusy $false
}

# ---------------- FASE 2: generar SPL parcheado (offline) ----------------
function Invoke-Phase2 {
    SetBusy $true
    SetStatus "Fase 2: generando SPL parcheado..."
    Log "=== FASE 2 (offline): gen_spl-unlock + chsize ==="
    $splLoader = Join-Path $here "splloader.bin"
    $splUnlock = Join-Path $here "spl-unlock.bin"
    $ubootRaw  = Join-Path $here "uboot.bin"
    $ubootBak  = Join-Path $here "uboot_bak.bin"
    $splStock  = Join-Path $here "u-boot-spl-16k-sign.bin"

    if ((Test-Path $splUnlock) -and -not (Test-Path $splLoader)) {
        Log "[OK] spl-unlock.bin ya existe; se usa el generado anteriormente."
        SetStatus "SPL parcheado listo" ([System.Drawing.Color]::Green)
        SetBusy $false
        return
    }
    if (-not (Test-Path $splLoader)) {
        Log "FALTA splloader.bin: ejecuta la FASE 1 primero (backup)."
        SetStatus "Falta el backup - ejecuta la Fase 1" ([System.Drawing.Color]::Firebrick)
        SetBusy $false
        return
    }
    $null = Invoke-Exe (Join-Path $here "gen_spl-unlock.exe") "splloader.bin"
    if (-not (Test-Path $splUnlock)) {
        Log "ERROR: no se generó spl-unlock.bin. NO continúes con la Fase 4."
        SetStatus "Fallo generando el SPL parcheado" ([System.Drawing.Color]::Firebrick)
        SetBusy $false
        return
    }
    if (Test-Path $ubootRaw) { $null = Invoke-Exe (Join-Path $here "chsize.exe") "uboot.bin" }
    if (Test-Path $splLoader) { Move-Item $splLoader $splStock -Force; Log "[OK] Backup SPL recortado -> u-boot-spl-16k-sign.bin" }
    if ((Test-Path $ubootRaw) -and -not (Test-Path $ubootBak)) { Move-Item $ubootRaw $ubootBak -Force; Log "[OK] Backup uboot recortado -> uboot_bak.bin" }
    $h1 = (Get-FileHash $splUnlock -Algorithm SHA256).Hash
    $h2 = (Get-FileHash $splStock  -Algorithm SHA256).Hash
    if ($h1 -ne $h2) {
        Log "[OK] spl-unlock.bin generado y distinto del SPL stock (parche aplicado correctamente)."
        SetStatus "SPL parcheado listo" ([System.Drawing.Color]::Green)
    } else {
        Log "AVISO: spl-unlock.bin es idéntico al SPL stock - el parche NO se aplicó."
        SetStatus "El parche no se aplicó" ([System.Drawing.Color]::Firebrick)
    }
    SetBusy $false
}

# ---------------- FASE 3: escribir cboot y verificar ----------------
function Invoke-Phase3 {
    SetBusy $true
    SetStatus "Fase 3: escribiendo cboot temporal..."
    Log "=== FASE 3: escribir cboot temporal en uboot_$($script:slot) y verificar ==="
    Log "Conecta el móvil en modo BootROM si no está conectado."
    $rb = Join-Path $here ("uboot-" + $script:slot + "-cboot-readback.bin")
    Remove-Item $rb -ErrorAction SilentlyContinue
    $rc = Invoke-Exe (Join-Path $here "spd_dump.exe") ("--wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec w uboot_" + $script:slot + " fdl2-cboot.bin read_part uboot_" + $script:slot + " 0 1047272 uboot-" + $script:slot + "-cboot-readback.bin reset")
    if (Test-Path $rb) {
        $hRb = (Get-FileHash $rb -Algorithm SHA256).Hash.ToLower()
        $hCb = (Get-FileHash (Join-Path $here "fdl2-cboot.bin") -Algorithm SHA256).Hash.ToLower()
        if ($hRb -eq $hCb) {
            Log "[VERIFICADO] El cboot está escrito correctamente (hash idéntico)."
            SetStatus "Fase 3 OK - cboot verificado" ([System.Drawing.Color]::Green)
        } else {
            Log "[FALLO] La relectura NO coincide. NO continúes con la Fase 4; restaura con la Fase 5."
            SetStatus "Fallo de verificación del cboot" ([System.Drawing.Color]::Firebrick)
        }
    } else {
        Log "[FALLO] No se generó la relectura. NO continúes con la Fase 4."
        SetStatus "Fallo en la Fase 3" ([System.Drawing.Color]::Firebrick)
    }
    SetBusy $false
}

# ---------------- FASE 4A: borrar SPL ----------------
function Invoke-Phase4A {
    if (-not (Test-Path (Join-Path $here "spl-unlock.bin"))) {
        Log "BLOQUEADO: no existe spl-unlock.bin. Ejecuta la FASE 2 antes de borrar el SPL."
        SetStatus "Falta spl-unlock.bin (Fase 2)" ([System.Drawing.Color]::Firebrick)
        return
    }
    $rb = Join-Path $here ("uboot-" + $script:slot + "-cboot-readback.bin")
    $ok = $false
    if (Test-Path $rb) {
        $ok = ((Get-FileHash $rb -Algorithm SHA256).Hash.ToLower() -eq (Get-FileHash (Join-Path $here "fdl2-cboot.bin") -Algorithm SHA256).Hash.ToLower())
    }
    if (-not $ok) {
        Log "BLOQUEADO: el cboot no está verificado. Ejecuta la FASE 3 y verifica OK antes de borrar el SPL."
        SetStatus "Verifica el cboot (Fase 3) antes de borrar" ([System.Drawing.Color]::Firebrick)
        return
    }
    $resp = [System.Windows.Forms.MessageBox]::Show($form, "Vas a BORRAR las dos copias del SPL del móvil.`nHasta completar la Fase 5 el móvil NO arrancará (pantalla negra).`n`n¿Continuar?", "Fase 4A - operación destructiva", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    SetBusy $true
    SetStatus "Fase 4A: borrando SPL..."
    Log "=== FASE 4A: borrar splloader y splloader_bak ==="
    $null = Invoke-Exe (Join-Path $here "spd_dump.exe") "--wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec e splloader e splloader_bak reset"
    Log "SPL borrado. El móvil está SIN bootloader de primera etapa: pasa YA a la Fase 4B."
    SetStatus "SPL borrado - ejecuta la Fase 4B" ([System.Drawing.Color]::DarkOrange)
    SetBusy $false
}

# ---------------- FASE 4B: ejecutar SPL parcheado ----------------
function Invoke-Phase4B {
    if (-not (Test-Path (Join-Path $here "spl-unlock.bin"))) {
        Log "BLOQUEADO: no existe spl-unlock.bin. Ejecuta la FASE 2 primero."
        SetStatus "Falta spl-unlock.bin (Fase 2)" ([System.Drawing.Color]::Firebrick)
        return
    }
    SetBusy $true
    SetStatus "Fase 4B: ejecutando SPL parcheado..."
    Log "=== FASE 4B: ejecutar el SPL parcheado (crea el estado de desbloqueo) ==="
    Log "Es NORMAL que acabe en 'CHECK_BAUD FAIL' o 'device removed': el SPL parcheado tomó el control."
    $null = Invoke-Exe (Join-Path $here "spd_dump.exe") "--wait 300 exec_addr 0x65015f08 fdl spl-unlock.bin 0x65000800"
    Log "Fase 4B lanzada. Espera unos segundos y continúa con la Fase 5 (el móvil suele reconectarse solo al BootROM)."
    SetStatus "Fase 4B lanzada - continúa con la Fase 5" ([System.Drawing.Color]::DarkOrange)
    SetBusy $false
}

# ---------------- FASE 5: restaurar + token + wipe ----------------
function Invoke-Phase5 {
    $bak1 = Join-Path $here "uboot_bak.bin"
    $bak2 = Join-Path $here "u-boot-spl-16k-sign.bin"
    if (-not (Test-Path $bak1) -or -not (Test-Path $bak2)) {
        Log "BLOQUEADO: faltan los backups (uboot_bak.bin / u-boot-spl-16k-sign.bin). Ejecuta las FASES 1 y 2."
        SetStatus "Faltan los backups" ([System.Drawing.Color]::Firebrick)
        return
    }
    $resp = [System.Windows.Forms.MessageBox]::Show($form, "La Fase 5 restaura la cadena de arranque stock, lee el token de desbloqueo y borra 'misc' (fuerza factory reset: BORRA TODOS LOS DATOS).`n`n¿Continuar?", "Fase 5 - restaurar y desbloquear", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    SetBusy $true
    SetStatus "Fase 5: restaurando y desbloqueando..."
    Log "=== FASE 5: restaurar stock + leer token + borrar misc ==="
    Log "El móvil suele reconectarse solo al BootROM; si no, reconéctalo (apagado + Vol- + USB)."
    Remove-Item (Join-Path $here "miscdata-after.bin") -ErrorAction SilentlyContinue
    $null = Invoke-Exe (Join-Path $here "spd_dump.exe") ("--wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec w uboot_" + $script:slot + " uboot_bak.bin w splloader u-boot-spl-16k-sign.bin w splloader_bak u-boot-spl-16k-sign.bin read_part miscdata 0 1048576 miscdata-after.bin w misc misc-wipe.bin reset")
    Test-UnlockToken
    SetBusy $false
}

# ---------------- verificación ----------------
function Test-UnlockToken {
    $md = Join-Path $here "miscdata-after.bin"
    if (-not (Test-Path $md)) {
        Log "[--] miscdata-after.bin no existe todavía."
        return
    }
    $bytes = [System.IO.File]::ReadAllBytes($md)
    if ($bytes.Length -lt 8256) { Log "[--] miscdata-after.bin demasiado pequeño."; return }
    $tok = $bytes[8192..8255]
    $nz = @($tok | Where-Object { $_ -ne 0 }).Count
    Log ("Token @8192: " + $nz + " de 64 bytes distintos de cero")
    Log (($tok | ForEach-Object { $_.ToString("X2") }) -join " ")
    if ($nz -gt 0) {
        Log ">>> MARCADOR DE DESBLOQUEO PRESENTE (valor de 32 bytes + 2 hashes de 16)."
        SetStatus "¡DESBLOQUEADO! Reinicia el móvil y comprueba fastboot getvar unlocked" ([System.Drawing.Color]::Green)
    } else {
        Log ">>> Token a ceros: el marcador NO se creó. La cadena stock está restaurada (el móvil vuelve a ser arrancable)."
        Log "    Puedes repetir las Fases 3 -> 4A -> 4B -> 5 verificando cada paso."
        SetStatus "Sin marcador de desbloqueo" ([System.Drawing.Color]::DarkOrange)
    }
}

function Invoke-Verify {
    SetBusy $true
    Log "=== Verificación del desbloqueo ==="
    Test-UnlockToken
    Log ""
    Log "--- Dispositivos USB ---"
    $br = Get-BootROMDevice
    $fb = Get-FastbootDevice
    if ($br) { Log ("[BootROM ] " + $br.FriendlyName + "  (" + $br.InstanceId + ")") } else { Log "[BootROM ] no detectado" }
    if ($fb) { Log ("[fastboot] " + $fb.FriendlyName + "  (" + $fb.InstanceId + ")") } else { Log "[fastboot] no detectado" }
    $fbExe = $null
    foreach ($c in @((Join-Path $here "platform-tools\fastboot.exe"), (Join-Path $here "fastboot.exe"), "fastboot")) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) { $fbExe = $cmd.Source; break }
    }
    if ($fbExe) {
        Log ""
        Log ("--- fastboot (" + $fbExe + ") ---")
        $null = Invoke-Exe $fbExe "devices"
        $null = Invoke-Exe $fbExe "getvar unlocked"
        $null = Invoke-Exe $fbExe "getvar current-slot"
        $null = Invoke-Exe $fbExe "getvar anti"
    } else {
        Log ""
        Log "[--] fastboot no encontrado. Pon el móvil en fastboot (apagado + Vol- + Power) para comprobar 'unlocked: yes'."
    }
    SetBusy $false
}

# ---------------- emergencia ----------------
function Invoke-Restore {
    $bak1 = Join-Path $here "uboot_bak.bin"
    $bak2 = Join-Path $here "u-boot-spl-16k-sign.bin"
    if (-not (Test-Path $bak1) -or -not (Test-Path $bak2)) {
        Log "BLOQUEADO: faltan los backups. Esta herramienta no puede restaurar sin ellos."
        SetStatus "Faltan los backups" ([System.Drawing.Color]::Firebrick)
        return
    }
    $resp = [System.Windows.Forms.MessageBox]::Show($form, "Esto restaura la cadena de arranque STOCK (el móvil vuelve a su estado anterior, bloqueado).`nÚsalo si algo fue mal. ¿Continuar?", "Restauración de emergencia", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($resp -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    SetBusy $true
    SetStatus "Restaurando cadena de arranque stock..."
    Log "=== RESTAURACIÓN DE EMERGENCIA: cadena stock ==="
    $null = Invoke-Exe (Join-Path $here "spd_dump.exe") ("--wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec w uboot_" + $script:slot + " uboot_bak.bin w splloader u-boot-spl-16k-sign.bin w splloader_bak u-boot-spl-16k-sign.bin reset")
    Log "Restauración lanzada. El móvil debería volver a su estado anterior."
    SetStatus "Restauración lanzada" ([System.Drawing.Color]::Green)
    SetBusy $false
}

# ---------------- comprobación de archivos del paquete ----------------
if ($missing.Count -gt 0) {
    [System.Windows.Forms.MessageBox]::Show("Faltan archivos en la carpeta:`n" + ($missing -join "`n") + "`n`nDescomprime el ZIP COMPLETO y ejecuta desde esa carpeta.", "SerenityUnlock - archivos incompletos", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

# ---------------- construcción de la ventana ----------------
$form = New-Object System.Windows.Forms.Form
$form.Text             = "SerenityUnlock - Desbloqueo bootloader Redmi A5 4G (serenity)"
$form.ClientSize       = New-Object System.Drawing.Size(760, 665)
$form.StartPosition    = "CenterScreen"
$form.FormBorderStyle  = "FixedSingle"
$form.MaximizeBox      = $false
$form.BackColor        = [System.Drawing.Color]::White

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "SerenityUnlock Tool"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 15, [System.Drawing.FontStyle]::Bold)
$lblTitle.Location = New-Object System.Drawing.Size(24, 12)
$lblTitle.AutoSize = $true
$form.Controls.Add($lblTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = "Redmi A5 4G (serenity) · Unisoc UMS9230E · flujo CVE-2022-38694 · basado en TomKing062/spreadtrum_flash"
$lblSub.ForeColor = [System.Drawing.Color]::Gray
$lblSub.Location = New-Object System.Drawing.Size(24, 50)
$lblSub.AutoSize = $true
$form.Controls.Add($lblSub)

$lblWarn = New-Object System.Windows.Forms.Label
$lblWarn.Text = "⚠ AVISO: borra TODOS los datos y puede inutilizar el móvil. Úsalo SOLO en un teléfono tuyo. Sigue el orden de fases."
$lblWarn.ForeColor = [System.Drawing.Color]::Firebrick
$lblWarn.Location = New-Object System.Drawing.Size(24, 72)
$lblWarn.AutoSize = $true
$form.Controls.Add($lblWarn)

function New-PhaseButton {
    param([string]$text, $handler, [int]$x, [int]$y)
    $b = New-Object System.Windows.Forms.Button
    $b.Text     = $text
    $b.Location = New-Object System.Drawing.Size($x, $y)
    $b.Size     = New-Object System.Drawing.Size(240, 34)
    $b.UseVisualStyleBackColor = $true
    $b.Add_Click($handler)
    $form.Controls.Add($b)
    $script:buttons += $b
}

New-PhaseButton "1. Detectar dispositivo"            { Invoke-Detect }    24 104
New-PhaseButton "2. Arreglar driver fastboot"        { Invoke-DriverFix } 284 104
New-PhaseButton "Fase 1 - Backup (solo lectura)"     { Invoke-Phase1 }    24 146
New-PhaseButton "Fase 2 - Generar SPL parcheado"     { Invoke-Phase2 }    284 146
New-PhaseButton "Fase 3 - Escribir cboot + verificar"{ Invoke-Phase3 }    24 188
New-PhaseButton "Fase 4A - Borrar SPL (destructivo)" { Invoke-Phase4A }   284 188
New-PhaseButton "Fase 4B - Ejecutar SPL parcheado"   { Invoke-Phase4B }   24 230
New-PhaseButton "Fase 5 - Restaurar + desbloquear"   { Invoke-Phase5 }    284 230
New-PhaseButton "Verificar desbloqueo"               { Invoke-Verify }    24 272
New-PhaseButton "Emergencia - Restaurar stock"       { Invoke-Restore }   284 272

$lblHelp = New-Object System.Windows.Forms.Label
$lblHelp.Text = "Regla de oro: pulsa el botón de la fase y DESPUÉS conecta el móvil (cada fase espera 300 s). Modo BootROM: apagado + Vol- + USB (pantalla negra = normal)."
$lblHelp.ForeColor = [System.Drawing.Color]::DimGray
$lblHelp.Location = New-Object System.Drawing.Size(24, 316)
$lblHelp.Size = New-Object System.Drawing.Size(712, 30)
$form.Controls.Add($lblHelp)

$script:logBox = New-Object System.Windows.Forms.TextBox
$script:logBox.Multiline  = $true
$script:logBox.ReadOnly   = $true
$script:logBox.ScrollBars = "Vertical"
$script:logBox.Font       = New-Object System.Drawing.Font("Consolas", 9)
$script:logBox.BackColor  = [System.Drawing.Color]::FromArgb(24, 24, 24)
$script:logBox.ForeColor  = [System.Drawing.Color]::Gainsboro
$script:logBox.Location   = New-Object System.Drawing.Size(24, 350)
$script:logBox.Size       = New-Object System.Drawing.Size(712, 272)
$form.Controls.Add($script:logBox)

$script:status = New-Object System.Windows.Forms.Label
$script:status.Text    = "Listo. Empieza con '1. Detectar dispositivo'."
$script:status.Font    = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$script:status.Location = New-Object System.Drawing.Size(24, 630)
$script:status.Size    = New-Object System.Drawing.Size(712, 24)
$form.Controls.Add($script:status)

Log "SerenityUnlock listo. Flujo recomendado:"
Log "  1. Detectar dispositivo  ->  2. Arreglar driver fastboot"
Log "  Fase 1 (backup)  ->  Fase 2 (SPL parcheado)  ->  Fase 3 (cboot + verificar)"
Log "  Fase 4A (borrar SPL)  ->  Fase 4B (SPL parcheado)  ->  Fase 5 (restaurar + desbloquear)"
Log "  Verificar desbloqueo.  Si algo falla: 'Emergencia - Restaurar stock'."
Log "Guía completa en README.md (mismo directorio)."

if ($env:SERENITY_AUTOTEST -eq "1") { $form.Dispose(); exit 0 }
[void]$form.ShowDialog()
