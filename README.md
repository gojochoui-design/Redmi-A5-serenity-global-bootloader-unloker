# Desbloqueo y recuperación — Redmi A5 4G (`serenity`) desde Windows

> ⚠️ **AVISO — LÉELO ANTES DE NADA**
> Esto actúa a nivel de BootROM y puede dejar el teléfono **totalmente inservible** si fallas.
> Úsalo **SOLO en un móvil que sea tuyo**. El desbloqueo **borra todos los datos** del usuario.
> Tras el borrado, Android puede pedir la **cuenta Google (FRP)** que estaba en el móvil: ten las credenciales.
> Perderás garantía y el aviso de arranque pasará a estado *orange* (normal en bootloader unlocked).
> El autor de esta guía no se hace responsable de ladrillos, pérdida de datos o mal uso.

## Dos formas de usarlo

- **Herramienta gráfica (recomendada):** ejecuta `SerenityUnlock.bat` - botones fase a fase, log en vivo, avisos de seguridad y botón de restauración de emergencia.
- **Flujo manual:** sigue los pasos de esta guía (los mismos comandos, a mano).

El paquete incluye platform-tools mínimos (adb/fastboot).

## Qué es esto

Procedimiento completo, probado de principio a fin, para **desbloquear el bootloader y recuperar** un
Redmi A5 4G (codename `serenity`) desde Windows usando el **modo descarga del BootROM** de Unisoc
(vulnerabilidad pública **CVE-2022-38694**). Funciona incluso con el móvil en el estado
`The system has been destroyed`, sin sistema y sin recovery: solo hace falta que entre en modo descarga.

Basado en el trabajo de:

- **[TomKing062/CVE-2022-38694_unlock_bootloader](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader)** (loaders, `gen_spl-unlock`, `chsize`, concepto del flujo por fases)
- **[TomKing062/spreadtrum_flash](https://github.com/TomKing062/spreadtrum_flash)** (`spd_dump`)
- Investigación de **NCC Group** sobre las vulnerabilidades BootROM de Unisoc

## Compatibilidad

| Probaron y funcionan | Valor |
|---|---|
| Modelo | Redmi A5 4G Global/LATAM (`25028RN03L`) |
| SoC | Unisoc **UMS9230E** (comercializado como T7250) |
| Almacenamiento | **eMMC** (nunca uses un paquete UFS) |
| Slots | A/B |
| Android | 15 Go |

**Otros modelos:** necesitan **su propio** paquete de loaders del release upstream.
Nunca uses `ums9230_universal_unlock_EMMC.zip` ni paquetes de otro SoC: pueden borrar particiones o dejar el móvil muerto.

## Contenido de la carpeta

| Fichero | Qué es |
|---|---|
| `spd_dump.exe` | Herramienta de flasheo por BootROM/FDL (open source) |
| `fdl1-dl.bin`, `fdl2-dl.bin` | Loaders del release 1.72 para UMS9230E |
| `custom_exec_no_verify_65015f08.bin` | Payload que ejecuta el exploit en el BootROM |
| `fdl2-cboot.bin` | CBoot temporal que se escribe en la partición `uboot` activa |
| `gen_spl-unlock.exe` | Genera el SPL parcheado (`spl-unlock.bin`) a partir del SPL leído del móvil |
| `chsize.exe` | Recorta el volcado de `uboot` a su tamaño real firmado |
| `misc-wipe.bin` | Imagen de 2 KiB que fuerza factory reset al arrancar |
| `fix_fastboot_driver.ps1` | Arregla la detección de fastboot en Windows (muy importante, ver Paso 0) |
| `check_unlock.ps1` | Comprueba si el desbloqueo se aplicó (token + fastboot) |
| `unlock_autopatch_9230.bat` | Batch original (flujo antiguo; esta guía lo sustituye por fases verificadas) |

Durante el proceso se generan además:

| Fichero | Qué es |
|---|---|
| `splloader.bin` (262 144 B) | Volcado en bruto del SPL del propio móvil (con padding) |
| `u-boot-spl-16k-sign.bin` (67 144 B) | SPL de fábrica recortado (copia de seguridad restaurable) |
| `uboot_bak.bin` (1 238 648 B en este build) | U-Boot de fábrica recortado (copia de seguridad restaurable) |
| `spl-unlock.bin` (67 144 B) | **SPL parcheado** para el desbloqueo |
| `miscdata-baseline.bin` / `miscdata-after.bin` | Estado de `miscdata` antes / después |
| `uboot-a-cboot-readback.bin` | Verificación de la escritura del cboot |

> 🔒 **No publiques en tu repo** volcados de particiones con datos únicos del móvil
> (`prodnv`, `l_fixnv*`, `l_runtimenv*`, `persist`, IMEIs, etc.). Los SPL/uboot son firmware y no
> contienen datos personales, pero los NV sí.

---

## Paso 0 — Arreglar la detección de fastboot en Windows (muy importante)

Síntoma: Windows ve el móvil como **"fastboot Gadget"**, pero `fastboot devices` sale vacío.
Causa: el driver genérico de `libwdi`/Zadig registra el GUID de interfaz equivocado.
`fastboot.exe` busca el GUID `{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}` y no lo encuentra.

Solución (requiere ser administrador, añade el GUID y reinicia el puerto USB):

```powershell
powershell -ExecutionPolicy Bypass -File .\fix_fastboot_driver.ps1
```

Comprueba después: `fastboot devices` debe listar el móvil.

## Paso 1 — Entrar en modo BootROM (modo descarga)

1. Apaga el móvil del todo (mantén *Power* hasta apagarse).
2. Mantén pulsado **Vol −** (bajar volumen).
3. Conecta el cable USB **sin soltar Vol −**. No pulses *Power*.
4. La pantalla se queda **en negro**: es normal (modo descarga no muestra nada).
5. Verifica en el Administrador de dispositivos: **`SPRD U2S Diag (COMx)`** → `USB\VID_1782&PID_4D00`.

> Regla de oro: **ejecuta primero el comando** (queda escuchando 300 s) y **conecta después** el móvil.
> Suelta Vol − en cuanto veas `Spreadtrum Boot Block version 1.1` en el log.

## Paso 2 — Fase 1: SOLO LECTURA (copia de seguridad del boot chain)

Nada se escribe aquí. Genera los volcados que luego servirán para restaurar:

```bat
spd_dump.exe --wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec r splloader r uboot read_part miscdata 0 1048576 miscdata-baseline.bin reset
```

Salida esperada: `splloader.bin` (262 144 B), `uboot.bin` (8 388 608 B), `miscdata-baseline.bin`.
Aviso `FDL2: incompatible partition` es **normal** (la lista de particiones se lee igual).

## Paso 3 — Fase 2 (offline): generar el SPL parcheado y recortar los backups

```bat
gen_spl-unlock.exe splloader.bin
chsize.exe uboot.bin
ren splloader.bin u-boot-spl-16k-sign.bin
ren uboot.bin uboot_bak.bin
```

Verifica: existe `spl-unlock.bin` (67 144 B) y es **distinto** de `u-boot-spl-16k-sign.bin`.
Si `gen_spl-unlock.exe` falla, **NO sigas**: sin SPL parcheado no hay desbloqueo.

## Paso 4 — Fase 3: escribir el cboot temporal y verificar

```bat
spd_dump.exe --wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec w uboot_a fdl2-cboot.bin read_part uboot_a 0 1047272 uboot-a-cboot-readback.bin reset
```

Verificación **obligatoria** antes de continuar:

```powershell
(Get-FileHash .\uboot-a-cboot-readback.bin).Hash -eq (Get-FileHash .\fdl2-cboot.bin).Hash
```

Debe dar `True` (ambos de 1 047 272 bytes, SHA-256 `7e047dc5…`). Si falla, **restaura antes de nada**:
`w uboot_a uboot_bak.bin` y rehaz esta fase.

> Si tu slot activo fuera **B** (compruébalo con `fastboot getvar current-slot`), cambia `uboot_a` por `uboot_b` en esta y en la fase 5.

## Paso 5 — Fase 4: borrar las SPL y ejecutar el SPL parcheado

```bat
spd_dump.exe --wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec e splloader e splloader_bak reset
```

A partir de aquí el móvil **no arranca** hasta restaurar (Paso 6). Ten todo listo y no cortes la energía.

```bat
spd_dump.exe --wait 300 exec_addr 0x65015f08 fdl spl-unlock.bin 0x65000800
```

Terminar en `EXEC FDL1` → `CHECK_BAUD FAIL` → `device removed, exiting...` es **normal y correcto**:
el SPL parcheado tomó el control. No lo repitas por ese motivo.

## Paso 6 — Fase 5: restaurar la cadena de arranque, leer el token y forzar el reset

El móvil suele reconectarse solo al BootROM (el listener espera 300 s). Si no, repite el Paso 1:

```bat
spd_dump.exe --wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec w uboot_a uboot_bak.bin w splloader u-boot-spl-16k-sign.bin w splloader_bak u-boot-spl-16k-sign.bin read_part miscdata 0 1048576 miscdata-after.bin w misc misc-wipe.bin reset
```

Salida esperada:

```
Write Part Done: uboot_a,     target: 0x12e678, written: 0x12e678
Write Part Done: splloader,   target: 0x10648,  written: 0x10648
Write Part Done: splloader_bak, target: 0x10648, written: 0x10648
Write Part Done: misc,        target: 0x800,    written: 0x800
```

## Paso 7 — Fase 6: verificar el desbloqueo

```powershell
powershell -ExecutionPolicy Bypass -File .\check_unlock.ps1
```

- `miscdata-after.bin`, token en el offset 8192:
  - **64 bytes a cero** → no se creó el marcador (sigue bloqueado; el móvil queda restaurado y arrancable).
  - **No ceros** (valor de 32 bytes + 2 hashes de 16) → **desbloqueo aplicado**.
- Comprobación definitiva en fastboot (apagado → **Vol − + Power**):

```
fastboot getvar unlocked     →  unlocked: yes
```

El arranque mostrará el aviso naranja de estado *unlocked*: es lo esperado.

---

## Recuperación de emergencia

Mientras el BootROM sea accesible (lo es siempre: está grabado en la ROM del chip), todo es recuperable.

**Restaurar la cadena de arranque stock** (volviendo al estado previo, bloqueado):

```bat
spd_dump.exe --wait 300 exec_addr 0x65015f08 fdl fdl1-dl.bin 0x65000800 fdl fdl2-dl.bin 0x9efffe00 exec w uboot_a uboot_bak.bin w splloader u-boot-spl-16k-sign.bin w splloader_bak u-boot-spl-16k-sign.bin reset
```

Si el móvil quedó **sin SPL** (pantalla negra, no arranca): no pasa nada, entra solo en modo descarga
(`VID_1782&PID_4D00`) y ejecuta el comando de arriba. **Nunca** intentes arrancar con el SPL borrado.

## Problemas frecuentes

| Síntoma | Solución |
|---|---|
| `find port failed` | Cierra, re-ejecuta el comando y reconecta el móvil (Vol − + USB) |
| `FDL2: incompatible partition` | Aviso normal; la lista de particiones se lee bien |
| Un solo `CHECK_BAUD FAIL` al inicio | Normal, continúa |
| `LIBUSB_ERROR_IO` repetidos | Desconecta, prueba otro puerto USB directo (sin hubs), re-ejecuta |
| `fastboot devices` vacío | Ejecuta `fix_fastboot_driver.ps1` como administrador |
| El token sale a ceros tras la fase 5 | La cadena stock ya está restaurada (móvil arrancable); repite fases 4–5 verificando antes el hash del cboot |
| Batería baja | Carga antes de empezar; no interrumpas escrituras |

## Después del desbloqueo

- Con el bootloader **unlocked**, `fastboot flash` ya funciona: puedes flashear la **ROM fastboot oficial completa** de la **región correcta** (Global/EEA/…).
- ⚠️ **Nunca flashees una región distinta a la del móvil con el bootloader bloqueado**: provoca `The system has been destroyed`.
- ⚠️ Respeta el **anti-rollback**: no instales builds más viejos que los que tenía el móvil (`fastboot getvar anti`).
- Tras el `misc-wipe`, el primer arranque hace factory reset y puede pedir la cuenta Google (FRP).

## Créditos

- **TomKing062** — [CVE-2022-38694_unlock_bootloader](https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader) y [spreadtrum_flash](https://github.com/TomKing062/spreadtrum_flash): todo el exploit y las herramientas base.
- **NCC Group** — análisis de las vulnerabilidades BootROM de Unisoc (CVE-2022-38694/38691/38692).
- Flujo adaptado, verificado y documentado para Windows sobre un Redmi A5 4G real (2026-10).

---

### English quick reference

1. Fix fastboot detection: run `fix_fastboot_driver.ps1` as admin (adds the interface GUID `{F72FE0D4-CBCB-407d-8814-9ED673D0DD6B}` Windows' `fastboot.exe` needs).
2. Enter Unisoc BootROM: power off, hold **Vol−**, plug USB (black screen is normal; device shows as `SPRD U2S Diag`, `VID_1782&PID_4D00`).
3. Run each `spd_dump` command **first**, then connect the phone (each one waits 300 s).
4. Phases: (1) read-only backup of `splloader` + `uboot` + `miscdata` → (2) `gen_spl-unlock` + `chsize` offline → (3) write `fdl2-cboot.bin` to the active `uboot` slot and **verify the readback hash** → (4) erase both SPL copies, boot the patched SPL (ends with `device removed` = OK) → (5) restore stock `uboot` + both SPL copies, re-read `miscdata`, wipe `misc` → (6) verify token and `fastboot getvar unlocked: yes`.
5. Only use on **your own device**; unlocking wipes all data; wrong-region or downgraded firmware on a locked bootloader causes `The system has been destroyed`.
