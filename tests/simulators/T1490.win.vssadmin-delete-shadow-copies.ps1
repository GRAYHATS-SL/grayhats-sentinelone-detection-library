# Simulador SEGURO para rules/14-impact/T1490.win.vssadmin-delete-shadow-copies.yml
#
# NO borra ninguna copia de sombra. Usa "/?" para forzar a vssadmin.exe a
# mostrar la ayuda del comando en vez de ejecutarlo, pero la línea de
# comandos del proceso creado SÍ contiene la cadena "delete shadows" que
# busca la regla.
#
# Uso: ejecutar en PowerShell (no hace falta ser administrador, /? no
# requiere privilegios elevados) en una máquina con el agente de
# SentinelOne y la regla en modo "Detect".

vssadmin delete shadows /?

Write-Host "Simulación completada. Revisa la consola de SentinelOne: deberías ver una alerta de 'Ransomware - Delete Volume Shadow Copies via vssadmin' en los próximos segundos."
