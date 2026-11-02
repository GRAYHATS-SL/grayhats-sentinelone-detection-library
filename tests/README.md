# Cómo testear una regla STAR

Nunca se pasa una regla de `Draft` a `Active` (con acción de bloqueo real) sin
haberla probado antes. Hay que validar **dos cosas distintas**, no una:

1. **La lógica de detección** — ¿la condición dispara cuando debe, y no dispara
   con actividad legítima (falsos positivos)?
2. **La acción de respuesta** — cuando dispara, ¿hace exactamente lo que
   creemos? Una detección perfecta con una acción mal targeteada puede seguir
   siendo destructiva (ver los ejemplos reales más abajo).

Ninguna de las dos se puede dar por buena solo con la sintaxis validando
(`scripts/validate_rules.py`) o con que "tiene buena pinta" — ambas se prueban
con evidencia.

## Fases de validación

| Fase | Qué se hace | Acción de la regla | Qué confirma |
|---|---|---|---|
| 1. Sintaxis | `python scripts/validate_rules.py` + pegar en la consola de STAR | — | La regla no tiene errores de formato/cabecera ni de sintaxis S1QL. |
| 2. Simulación histórica ("On-Hit"/Preview) | En la consola, al asignar la regla, usar la simulación sobre telemetría de las últimas 24-48h | — | Cuántos endpoints la habrían disparado con datos reales, sin ejecutar nada. Señal temprana de exclusiones que faltan. |
| 3. Prueba manual con simulador inofensivo | Ejecutar en 1-2 máquinas de prueba un script que imite el patrón exacto (ver `simulators/`) | `Detect` | La lógica de detección dispara con el patrón esperado. |
| 4. Observación en producción | Desplegar en `Detect` al grupo/site objetivo durante 1-2 semanas | `Detect` | Caza de falsos positivos reales, en tráfico real. Se documenta en `results/`. |
| 5. Prueba de la acción de respuesta | En una VM desechable/aislada, ejecutar el mismo simulador con la acción real habilitada | `KillAndQuarantine` / `DisconnectNetwork` / etc. | Qué mata/pone en cuarentena/aísla exactamente la acción — no solo que detecta. |
| 6. Paso a producción | Activar la regla con su acción real | Real | Solo tras 4 y 5 confirmados y documentados. |

La fase 5 es la que más se salta y la que más duele saltarse: confirma cosas
como si `KillAndQuarantine` pone en cuarentena el artefacto malicioso o el
propio proceso padre legítimo (p. ej. `winword.exe` en
[`office-child-process-suspicious-args.yml`](../rules/04-execution/T1204.002.win.office-child-process-suspicious-args.yml)),
o si `DisconnectNetwork` aísla solo al atacante o al servidor completo (ver la
nota bloqueante en
[`network-share-mass-encryption.yml`](../rules/14-impact/T1486.win.network-share-mass-encryption.yml)).

## Reglas de seguridad para las pruebas

- **Nunca ejecutar la acción maliciosa real**, ni de prueba: nada de
  `vssadmin delete shadows /all` de verdad, nada de cifrar archivos reales.
  Usa variantes inofensivas que generen el mismo patrón de comando/evento
  (`/?` para ver ayuda sin ejecutar, `echo` en vez de invocar de verdad,
  ficheros dummy en una carpeta de prueba dedicada).
- La fase 5 (acción real) se ejecuta **solo** en una VM desechable/aislada de
  red, nunca en un endpoint de producción ni en un servidor real.
- Documenta siempre el resultado en `results/`, aunque sea "sin hallazgos" —
  es la evidencia que justifica pasar `Estado: Draft` a `Estado: Active` en el
  archivo de la regla (ver el flujo en el [README principal](../README.md)).

## Estructura de `tests/`

```
tests/
├── simulators/       # scripts inofensivos que imitan el patrón exacto de una regla (.ps1, .vbs, .sh...)
├── test-plans/       # checklist en markdown de cómo probar cada regla — no siempre hay script:
│                     #   a veces es "abre Word y activa macros", o "revisa el On-Hit en la consola"
└── results/          # evidencia de cada ronda de pruebas: fecha, entorno, hallazgos, decisión
```

Los tres se nombran igual que el archivo de regla (sin extensión), para que
sea evidente a qué regla pertenece cada uno:

```
rules/14-impact/T1490.win.vssadmin-delete-shadow-copies.yml
tests/simulators/T1490.win.vssadmin-delete-shadow-copies.ps1
tests/test-plans/T1490.win.vssadmin-delete-shadow-copies.md
tests/results/T1490.win.vssadmin-delete-shadow-copies.md
```

No todas las reglas van a tener las tres cosas: algunas no admiten un
simulador seguro (p. ej. una detección que solo se puede probar con datos
reales de producción) y su `test-plan.md` describirá el procedimiento manual
en vez de apuntar a un script.

## Ejemplo completo

Ver [`simulators/T1490.win.vssadmin-delete-shadow-copies.ps1`](simulators/T1490.win.vssadmin-delete-shadow-copies.ps1),
[`test-plans/T1490.win.vssadmin-delete-shadow-copies.md`](test-plans/T1490.win.vssadmin-delete-shadow-copies.md) y
[`results/T1490.win.vssadmin-delete-shadow-copies.md`](results/T1490.win.vssadmin-delete-shadow-copies.md)
como referencia de cómo documentar una ronda de pruebas.
