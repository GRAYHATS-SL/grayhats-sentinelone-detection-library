# Índice de reglas

Listado de todas las reglas STAR del repositorio, agrupadas por la carpeta
numerada (táctica MITRE ATT&CK, en orden de kill chain) en la que viven.
Actualizar esta tabla cada vez que se añada, mueva o retire una regla.

Los archivos siguen el formato `<técnica>[.<subtécnica>].<so>.<nombre>.yml`
(`win`/`lnx`/`mac` según el campo `os` de la regla — ver
[README principal](../README.md#formato-de-nombre-de-archivo)).

La columna **Sintaxis** refleja el campo `syntax_checked` del archivo: ✅ significa
que la query se pegó en la consola de SentinelOne y se comprobó que la sintaxis
es válida (no que la regla esté validada con Atomic Red Team —eso es
`validation_status`—, ni que esté en `Active`, ni que se hayan corrido todas las
fases de [`tests/README.md`](../tests/README.md)). ⚠️ significa que se comprobó y
se encontró un problema que sigue pendiente de resolver del todo. — significa
que no se ha comprobado.

Tácticas sin reglas todavía (carpeta creada con `.gitkeep`, pendiente de
contenido): `01-reconnaissance`, `02-resource-development`,
`03-initial-access`, `10-discovery`.

> **Nota ATT&CK v19 (28 abril 2026):** Defense Evasion (TA0005) se retiró y se
> partió en **Stealth** (hereda TA0005) y **Defense Impairment** (TA0112).
> Enterprise pasa de 14 a 15 tácticas y Defense Impairment entra en la posición
> 8 de la matriz, por lo que las carpetas 08–14 se renumeraron a 09–15. Las
> técnicas T1562/T1562.001/T1562.006 se fusionaron en **T1685** y T1562.003 se
> reemitió como **T1690**; las reglas afectadas cambiaron de ID, de nombre de
> archivo y de carpeta.

## 04-execution — Execution

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1204.002.win.office-application-spawns-script-interpreter-or-lolbin.yml`](04-execution/T1204.002.win.office-child-process-suspicious-args.yml) | T1204.002 (sec.: T1566.001) | Critical | Draft | ✅ | Detecta aplicaciones de Office lanzando intérpretes o LOLBins (PowerShell, cmd, wscript, mshta, regsvr32, rundll32, certutil, bitsadmin). |
| [`T1059.001.win.suspicious-script-execution-from-anomalous-path.yml`](04-execution/T1059.001.win.suspicious-script-execution-from-anomalous-path.yml) | T1059.001 (sec.: T1204.002) | Medium | Draft | ✅ | Detecta intérpretes de scripts (PowerShell, wscript, cscript, cmd, mshta) ejecutándose con rutas de usuario o temporales anómalas (`%TEMP%`, `%APPDATA%`, `Public`, `ProgramData`, `Downloads`...) en la cmdline. Genérica, en modo `Detect` para cazar comportamiento anómalo, no para bloquear. 


## 05-persistence — Persistence

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1547.001.win.run-key-suspicious-payload.yml`](05-persistence/T1547.001.win.run-key-suspicious-payload.yml) | T1547.001 | High | Draft | ✅ | Detecta la escritura en claves Run/RunOnce de un valor sospechoso: ruta anómala (`%TEMP%`, `%APPDATA%`, `Public`...), intérprete con argumentos de descarga/ofuscación, o LOLBin (`rundll32`, `regsvr32`, `certutil`, `bitsadmin`). |
| [`T1053.005.win.scheduled-task-creation-with-payload-in-suspicious-path.yml`](05-persistence/T1053.005.win.scheduled-task-creation-with-payload-in-suspicious-path.yml) | T1053.005 | High | Draft | ✅ | Detecta `schtasks.exe /create` con `/tr` apuntando a un binario o script en rutas de usuario o temporales sospechosas (`%TEMP%`, `%APPDATA%`, `Public`, `ProgramData`...). Solo cubre la vía `/tr`; `/xml` queda para otra regla. |

## 06-privilege-escalation — Privilege Escalation

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1134.001.win.execution-potato-family-tools.yml`](06-privilege-escalation/T1134.001.win.execution-potato-family-tools.yml) | T1134.001 (sec.: T1068) | Critical | Draft | — | Ángulo firma: detecta herramientas de la familia Potato (JuicyPotato, RoguePotato, PrintSpoofer, GodPotato...) por nombre de binario y CLSID/flags característicos de línea de comandos. Evadible por renombrado. |
| [`T1134.win.process-elevated-to-system-from-service-parent.yml`](06-privilege-escalation/T1134.win.process-elevated-to-system-from-service-parent.yml) | T1134 (sec.: T1134.001, T1134.002) | Critical | Draft | ✅ | Detecta una cuenta de servicio (LOCAL SERVICE, NETWORK SERVICE, IIS APPPOOL, NT SERVICE) creando un proceso SYSTEM — firma del abuso de SeImpersonatePrivilege (Potato/PrintSpoofer/GodPotato). |
| [`T1134.win.token-manipulation-tools-and-commands.yml`](06-privilege-escalation/T1134.win.token-manipulation-tools-and-commands.yml) | T1134 (sec.: T1134.001) | High | Draft | — | Ángulo firma: detecta herramientas (incognito, Tokenvator) y cmdlets/APIs de manipulación de tokens (`Invoke-TokenManipulation`, `AdjustTokenPrivileges`...), más la firma del `getsystem` de Meterpreter por named pipe. |

## 07-stealth — Stealth

Antes `07-defense-evasion`. Stealth hereda TA0005: el adversario **se esconde**,
las defensas siguen funcionando. Lo que las **rompe** está en
[`08-defense-impairment`](#08-defense-impairment--defense-impairment).

Primera táctica con reglas para **Linux** además de Windows, y primeras
reglas mapeadas a **Atomic Red Team** (campos `art_test`/`art_technique`/
`tests_included`/`test_guids`/`coverage`/`syntax_checked`/`last_validated`).

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1014.lnx.diamorphine-magic-signal.yml`](07-stealth/T1014.lnx.diamorphine-magic-signal.yml) | T1014 (sec.: T1548) | Critical | Draft | — | ART T1014 #4 (`coverage: partial`, solo el control por señales): `kill -31/-63/-64`, interfaz de control del rootkit Diamorphine. Cruza a Privilege Escalation (`-63` da root). Duplica motor nativo: no. |
| [`T1014.lnx.ld-so-preload-hijack.yml`](07-stealth/T1014.lnx.ld-so-preload-hijack.yml) | T1014 (sec.: T1574.006) | Critical | Draft | — | ART T1014 #3 (`coverage: full`): modificación de `/etc/ld.so.preload` para inyectar una librería en todo proceso (rootkits tipo libprocesshider). Cruza a Persistence y Privilege Escalation. |
| [`T1014.lnx.lkm-rootkit.yml`](07-stealth/T1014.lnx.lkm-rootkit.yml) | T1014 | Critical | Draft | — | ART T1014 #1, #2, #4 (`coverage: full`, fase de carga): `insmod`/`modprobe` de un módulo del kernel (incl. Diamorphine). Duplica motor nativo: parcial (el motor de comportamiento de SentinelOne ya vigila carga de módulos). |
| [`T1070.003.lnx.clear-bash-history-file.yml`](07-stealth/T1070.003.lnx.clear-bash-history-file.yml) | T1070.003 | High | Draft | — | ART T1070.003 #1-#5 (`coverage: full`, ángulo comando): borrado/vaciado/truncado de `.bash_history` y equivalentes vía `rm`/`echo`/`cat`/`ln`/`truncate`. |
| [`T1070.003.lnx.clear-bash-history-file-event.yml`](07-stealth/T1070.003.lnx.clear-bash-history-file-event.yml) | T1070.003 | High | Draft | — | ART T1070.003 #1-#5 (`coverage: full`, ángulo fichero): mismo objetivo que la regla anterior pero por evento de fichero — más robusta frente a redirecciones del shell que no generan proceso propio. |
| [`T1070.003.lnx.history-evasion-special.yml`](07-stealth/T1070.003.lnx.history-evasion-special.yml) | T1070.003 | Medium | Draft | — | ART T1070.003 #9-#10 (`coverage: full`): `ssh -T` (evita lastlog/wtmp) y truncado de logs de Docker. Dos técnicas heterogéneas agrupadas por pertenecer al mismo test ART. |
| [`T1070.003.win.clear-powershell-history.yml`](07-stealth/T1070.003.win.clear-powershell-history.yml) | T1070.003 | High | Draft | ✅ | ART T1070.003 #14 (`coverage: full`, ángulo comando): `Clear-History` vía PowerShell. |

## 08-defense-impairment — Defense Impairment

Táctica nueva en ATT&CK v19 (TA0112): el adversario **rompe** activamente las
defensas, en vez de esconderse de ellas. Todas las reglas de esta carpeta
vienen de la antigua `07-defense-evasion` o son posteriores al split.

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1685.win.disable-sentinelone-agent.yml`](08-defense-impairment/T1685.win.disable-sentinelone-agent.yml) | T1685 (antes T1562.001) | Critical | Draft | — | Detecta intentos de detener, deshabilitar o desinstalar el propio agente de SentinelOne (`SentinelCTL`, `sc`/`net`/`taskkill`/`msiexec`/`reg` contra los servicios o la instalación de SentinelOne). Máxima prioridad: protege al EDR mismo. |
| [`T1685.win.disable-windows-defender.yml`](08-defense-impairment/T1685.win.disable-windows-defender.yml) | T1685 (antes T1562.001) | High | Draft | — | Detecta comandos que deshabilitan o debilitan Windows Defender (`Set-MpPreference`, `sc`/`net stop windefend`, exclusiones de ruta/proceso/extensión). |
| [`T1685.005.win.clear-logs.yml`](08-defense-impairment/T1685.005.win.clear-logs.yml) | T1685.005 (antes T1070.001) | High | Draft | ✅ | Detecta borrado de canales de logs de eventos. |
| [`T1690.lnx.disable-history-logging.yml`](08-defense-impairment/T1690.lnx.disable-history-logging.yml) | T1690 (antes T1070.003; sec.: Persistence) | High | Draft | — | ART #6-#7 (`coverage: full`): `unset HISTFILE`, `HISTFILESIZE=0`, `history -c`, `set +o history`. El #7 (persistente en `.bashrc`) cruza a Persistence. |
| [`T1690.lnx.disable-history-logging-profile-event.yml`](08-defense-impairment/T1690.lnx.disable-history-logging-profile-event.yml) | T1690 (antes T1070.003; sec.: Persistence) | High | Draft | — | ART #7 (`coverage: partial`, ángulo fichero): modificación de `.bashrc`/`.profile`/etc. Ruidosa (dispara con cualquier cambio de perfil) — mejor como hunting si el tenant no expone el diff del contenido. |
| [`T1690.win.disable-powershell-history.yml`](08-defense-impairment/T1690.win.disable-powershell-history.yml) | T1690 | High | Draft | ✅ | Detecta si el historial de comandos de powershell se deshabilita. |

## 09-credential-access — Credential Access

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1003.001.win.lsass-memory-dump.yml`](09-credential-access/T1003.001.win.lsass-memory-dump.yml) | T1003.001 | Critical | Draft | ✅ | Detecta cuando un proceso abre un handle en modo lectura hacia el proceso lsass.exe. Posible volcado de credenciales. |

## 11-lateral-movement — Lateral Movement

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1021.002.win.lateral-movement-payload-creation.yml`](11-lateral-movement/T1021.002.win.lateral-movement-payload-creation.yml) | T1021.002 | High | Draft | ✅ | Detecta la creación de posibles payloads ejecutables fuente de un movimiento lateral. |
| [`T1021.002.win.remote-admin-shares-accessed.yml`](11-lateral-movement/T1021.002.win.remote-admin-shares-accessed.yml) | T1021.002 | High | Draft | ✅ | Detecta el acceso a Admin Shares remotos desde el punto de vista del equipo que inicia la conexión. |
| [`T1021.001.win.rdp-inbound-critical-assets.yml`](11-lateral-movement/T1021.001.win.rdp-inbound-critical-assets.yml) | T1021.001 | High | Draft | — | Detecta RDP entrante hacia activos críticos (DCs, servidores sensibles) desde orígenes fuera de una allowlist estricta de admins. Ángulo "destino de alto valor". |
| [`T1021.001.win.rdp-inbound-workstation.yml`](11-lateral-movement/T1021.001.win.rdp-inbound-workstation.yml) | T1021.001 | High | Draft | — | Detecta sesiones RDP entrantes hacia workstations de usuario (no servidores) desde orígenes no admin — ángulo "destino", cubre atacantes sin agente en origen. |
| [`T1021.001.win.rdp-outbound.yml`](11-lateral-movement/T1021.001.win.rdp-outbound.yml) | T1021.001 | Medium | Draft | — | Detecta RDP saliente hacia IPs internas (RFC1918) desde equipos que no están en la lista de administradores — ángulo "origen", identifica quién se mueve. |
| [`T1021.006.win.inbound-remote-wmi-winrm-no-admins.yml`](11-lateral-movement/T1021.006.win.inbound-remote-wmi-winrm-no-admins.yml) | T1021.006 (sec.: T1047) | High | Draft | — | Detecta conexiones entrantes a los puertos de WinRM (5985/5986) y WMI/DCOM (135) desde orígenes no admin — ángulo "destino", complementa a la regla por cmdline. |
| [`T1047.win.remote-execution-wmi-winrm.yml`](11-lateral-movement/T1047.win.remote-execution-wmi-winrm.yml) | T1047 (sec.: T1021.006) | High | Draft | — | Detecta ejecución remota vía WMI/WinRM desde dos ángulos: cmdlets en el origen (`Invoke-Command`, `New-CimSession`...) e hijos de `WmiPrvSE.exe`/`winrshost.exe` en el destino. En `Detect`: la exclusión de SYSTEM se retiró porque cegaba la rama del destino. |
| [`T1021.002.win.remote-service-creation.yml`](11-lateral-movement/T1021.002.win.remote-service-creation.yml) | T1021.002 (sec.: T1543.003) | High | Draft | — | Detecta `sc.exe` creando un servicio en una ruta UNC remota (`\\host\...` + `create`). **No detecta PsExec** (usa SVCCTL/SMB directo, no sc.exe) — para eso ver `T1021.002.win.psexec-service-exec.yml`. |

## 12-collection — Collection

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1560.001.win.pre-exfiltration-archiving.yml`](12-collection/T1560.001.win.pre-exfiltration-archiving.yml) | T1560.001 / T1074.001 | Medium | Draft | — | Detecta compresión de archivos (7z, WinRAR, `Compress-Archive`) con contraseña o máxima compresión en rutas de usuario — preparación típica de datos ("staging") antes de exfiltrarlos. |

## 13-command-and-control — Command and Control

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1071.001.win.c2-direct-to-ip.yml`](13-command-and-control/T1071.001.win.c2-direct-to-ip.yml) | T1071.001 | High | Draft | — | Detecta LOLBins/intérpretes (PowerShell, wscript/cscript, mshta, rundll32, regsvr32, msbuild, installutil) conectando directamente a una IP pública — señal por sí sola, sin depender del check "sin DNS previo" (no viable, ver notas). |
| [`T1071.004.win.c2-dns-tunneling.yml`](13-command-and-control/T1071.004.win.c2-dns-tunneling.yml) | T1071.004 (sec.: T1568.002) | High | Draft | — | Detecta subdominios DNS anormalmente largos con aspecto hexadecimal, indicativos de tunelización DNS o DGA. Solapa con `T1048.001.win.dns-exfiltration.yml` (misma señal técnica, distinta clasificación MITRE). |
| [`T1071.001.win.c2-https-beaconing.yml`](13-command-and-control/T1071.001.win.c2-https-beaconing.yml) | T1071.001 | Critical | Draft | — | Aproximación gruesa a beaconing: cuenta conexiones salientes de LOLBins estrictos (rundll32, regsvr32, mshta, wscript, cscript) que superan un umbral en una ventana (`trigger`). Incluye `power_query_hunting` complementaria con análisis real de periodicidad (jitter) por destino — ver también `scripts/c2c_beaconing_analyzer.py`. |
| [`T1571.win.c2-known-c2c-frameworks.yml`](13-command-and-control/T1571.win.c2-known-c2c-frameworks.yml) | T1571 | Critical | Draft | — | Detecta conexiones salientes a puertos por defecto de frameworks ofensivos conocidos (4444 Metasploit, 50050 Cobalt Strike, 9050/9051 Tor, etc.), sin filtrar por proceso — la fidelidad la da el puerto. |
| [`T1071.001.win.c2-known-tools-high-confidence.yml`](13-command-and-control/T1071.001.win.c2-known-tools-high-confidence.yml) | T1071.001 (sec.: T1105) | Critical | Draft | — | Cadenas de cmdline de alta fiabilidad de frameworks C2 (meterpreter, msfvenom, cobaltstrike, sliver-client/server, brute-ratel...). |
| [`T1071.001.win.c2-known-tools-low-confidence.yml`](13-command-and-control/T1071.001.win.c2-known-tools-low-confidence.yml) | T1071.001 | High | Draft | — | Cadenas de nombres de framework que también son palabras/productos legítimos (empire, sliver, grunt, ninja, apollo...) — solo dispara si además el proceso es un intérprete/LOLBin, y nunca en modo bloqueo. |
| [`T1059.win.c2-netcat-listener.yml`](13-command-and-control/T1059.win.c2-netcat-listener.yml) | T1059 (sec.: T1571) | Critical | Draft | — | Detecta netcat/ncat/powercat en modo listener, con regex tolerante al orden de flags (`-lvp`, `-nlvp`, `-lp`...). |
| [`T1059.win.c2-reverse-shell.yml`](13-command-and-control/T1059.win.c2-reverse-shell.yml) | T1059 (sec.: T1071.001) | Critical | Draft | — | Dirección saliente (reverse shell): netcat/socat con `-e`/`-c`/`exec`, más un patrón que caza binarios renombrados por la firma `-e <intérprete>` independientemente del nombre del ejecutable. |
| [`T1071.001.win.c2-uncommon-ports-protocol.yml`](13-command-and-control/T1071.001.win.c2-uncommon-ports-protocol.yml) | T1071.001 (sec.: T1571) | High | Draft | — | Detecta intérpretes/binarios de sistema conectando a puertos > 1024 fuera de la lista de puertos altos habituales (3389, 8080, 8443). Solapa con `T1048.003.win.to-uncommon-ports-exfiltration.yml`. |
| [`T1571.win.c2-anomalous-process-listening-on-port.yml`](13-command-and-control/T1571.win.c2-anomalous-process-listening-on-port.yml) | T1571 (sec.: T1059) | High | Draft | — | Detecta procesos no habituales abriendo un puerto de escucha (`IP Listen`) — más difícil de evadir que la detección por nombre porque no depende del binario. |
| [`T1071.001.win.c2-cobalt-strike-named-pipes.yml`](13-command-and-control/T1071.001.win.c2-cobalt-strike-named-pipes.yml) | T1071.001 (sec.: T1055) | Critical | Draft | — | Detecta named pipes con patrones por defecto de Cobalt Strike (`msagent_`, `postex_`, `MSSE-...`) — caza C2 inyectado en memoria sin cadenas en cmdline. Tipo de evento/campo pendiente de confirmar contra el esquema real del tenant. |
| [`T1001.002.win.c2-data-obfuscation-via-steganography.yml`](13-command-and-control/T1001.002.win.c2-data-obfuscation-via-steganography.yml) | T1001.002 | High | Draft | — | Detecta la creación de archivos de imagen (`jpg`, `jpeg`, `png`, `bmp`, `gif`, `tiff`, `tif`) resultantes de ocultar datos en ficheros de apariencia legítima mediante esteganografía. |

## 14-exfiltration — Exfiltration

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1048.001.win.dns-exfiltration.yml`](14-exfiltration/T1048.001.win.dns-exfiltration.yml) | T1048.001 (sec.: T1071.004) | High | Draft | — | Detecta consultas DNS con subdominios largos de aspecto hexadecimal/base64, indicativas de tunelización DNS para exfiltración. |
| [`T1048.002.win.email-exfiltration.yml`](14-exfiltration/T1048.002.win.email-exfiltration.yml) | T1048.002 (sec.: T1059.001) | High | Draft | — | Detecta envío de correo con adjuntos desde línea de comandos (`Send-MailMessage`, `blat`, `sendemail`, `swaks`, `mailsend`, `curl smtp://`), posible vía de exfiltración vía email. |
| [`T1030.win.high-volume-data-transfer.yml`](14-exfiltration/T1030.win.high-volume-data-transfer.yml) | T1030 | High | Draft | — | **Especulativa**: pretende detectar transferencia saliente de gran volumen, pero requiere agregación/umbral que no está confirmado que exista en S1QL 2.0. Traía un placeholder de regex roto (`matches '...'`) ya corregido — hay que volver a probar en consola. |
| [`T1048.002.win.https-exfiltration.yml`](14-exfiltration/T1048.002.win.https-exfiltration.yml) | T1048.002 / T1567.002 | High | Draft | — | Detecta intérpretes/LOLBins (PowerShell, curl, wget, certutil, bitsadmin) invocados con argumentos de subida HTTP(S) (`-Method POST/PUT/PATCH`, `-InFile`, `--upload-file`). Detección sobre `Process Creation`, no sobre el evento de red (la cmdline no está poblada ahí). |
| [`T1048.003.win.to-uncommon-ports-exfiltration.yml`](14-exfiltration/T1048.003.win.to-uncommon-ports-exfiltration.yml) | T1048.003 (sec.: T1071.001) | Medium | Draft | — | Detecta conexiones salientes de procesos de sistema/red (PowerShell, netcat, ncat) a puertos > 1024 fuera de los altos habituales (3389, 8080, 8443). |

## 15-impact — Impact

| Regla | Técnica MITRE | Severidad | Estado | Sintaxis | Objetivo |
|---|---|---|---|---|---|
| [`T1490.win.vssadmin-delete-shadow-copies.yml`](15-impact/T1490.win.vssadmin-delete-shadow-copies.yml) | T1490 | Critical | Draft | — | Detecta el borrado (`delete shadows`) o la reducción forzada del almacenamiento (`resize shadowstorage`) de las copias de sombra de volumen vía `vssadmin.exe` — paso previo casi universal al cifrado en el ransomware moderno, ya que elimina la vía de recuperación nativa de Windows. |
| [`T1490.win.delete-backups-via-wbadmin.yml`](15-impact/T1490.win.delete-backups-via-wbadmin.yml) | T1490 | Critical | Draft | — | Complementa la regla de `vssadmin`: detecta `wbadmin.exe delete backup/catalog/systemstatebackup`, el equivalente para Windows Server Backup. |
| [`T1490.win.bcdedit-disable-recovery.yml`](15-impact/T1490.win.bcdedit-disable-recovery.yml) | T1490 | High | Draft | — | Matar procesos bcdedit que desactiven WinRE o la reparación automática de arranque. |
| [`T1489.win.stopping-critical-services.yml`](15-impact/T1489.win.stopping-critical-services.yml) | T1489 | High | Draft | — | Detecta la detención de servicios de bases de datos o backup (SQL, Veeam, Acronis, Commvault, ShadowProtect) vía `net stop`/`sc stop` — preludio habitual del cifrado en ransomware. |
| [`T1486.win.network-share-mass-encryption.yml`](15-impact/T1486.win.network-share-mass-encryption.yml) | T1486 | Critical | Draft | — | Corre en el **servidor de archivos**. Detecta que archivos dentro de un recurso compartido de red están siendo renombrados con extensiones de ransomware conocidas, señal de que un equipo cliente está cifrando el share de forma remota. Aísla de red al servidor completo — solo debe aplicarse al grupo de servidores de archivos. |
| [`T1486.win.mapped-drive-encryption-client.yml`](15-impact/T1486.win.mapped-drive-encryption-client.yml) | T1486 | Critical | Draft | — | Corre en la **máquina cliente/atacante**, complementando a la regla anterior: detecta el proceso local que está escribiendo/cifrando archivos en una unidad de red mapeada o ruta UNC, e identifica y mata ese proceso concreto en vez de aislar el servidor entero. |
| [`T1490.win.vss-creation-error.yml`](15-impact/T1490.win.vss-creation-error.yml) | T1490 (sec.: T1685) | Medium | Draft | — | Regla **operativa**, no de amenazas: alerta cuando el servicio VSS registra un error (evento 12289/8193/11/25), útil tanto para salud de backups como para detectar manipulación. IDs 11/25 pendientes de verificar contra logs reales. |

## Herramientas complementarias (`scripts/`)

- [`scripts/c2c_beaconing_analyzer.py`](../scripts/c2c_beaconing_analyzer.py): analiza exportaciones de eventos `IP Connect` y calcula la regularidad de intervalos (coeficiente de variación) por tupla proceso/destino, para identificar beaconing real más allá de lo que `T1071.001.win.c2-https-beaconing.yml` puede aproximar dentro de una regla STAR. Requiere `pandas`/`numpy`/`matplotlib` — ver [`scripts/requirements-analysis.txt`](../scripts/requirements-analysis.txt) (deps separadas de las del validador, no hace falta instalarlas solo para validar reglas). Modo demo: `python scripts/c2c_beaconing_analyzer.py --demo`.

## Cómo mantener este índice

Al añadir una regla nueva:
1. Añade una fila en la tabla de su carpeta numerada (crea la sección si es la primera regla de esa táctica).
2. Objetivo en 1-2 frases: qué detecta y por qué importa, no una copia del `query`.
3. Mantén la columna **Estado** sincronizada con el campo `status` del archivo, y **Sintaxis** con el campo `syntax_checked` — cuando cambien, actualízalos aquí también en el mismo commit.
4. Nombra el archivo `<técnica>[.<subtécnica>].<so>.<nombre-descriptivo>.yml`, coherente con `mitre.techniques[0].id` y `os` de la regla (ver [README principal](../README.md#formato-de-nombre-de-archivo)).
