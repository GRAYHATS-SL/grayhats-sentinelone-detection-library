# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
El proyecto aún no tiene versiones etiquetadas — todo vive bajo
`[Unreleased]` hasta el primer release público.

## [Unreleased]

### Añadido
- Reglas de detección STAR para Windows y Linux cubriendo 11 de las 15
  tácticas de MITRE ATT&CK Enterprise v19 (Execution, Persistence,
  Privilege Escalation, Stealth, Defense Impairment, Credential Access,
  Lateral Movement, Collection, Command and Control, Exfiltration, Impact).
- `schemas/star-rule.schema.json`: JSON Schema que valida la estructura de
  cada regla (metadatos MITRE, severidad, acción, query S1QL, integración
  opcional con Atomic Red Team).
- `scripts/validate_rules.py`: valida cada regla contra el schema, que la
  táctica coincida con la carpeta, y que la técnica/SO del nombre de
  archivo coincidan con el contenido.
- `scripts/c2c_beaconing_analyzer.py`: herramienta de apoyo DFIR para
  analizar exportaciones de eventos de red y calcular la regularidad de
  intervalos (detección de beaconing por jitter).
- Integración con [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team):
  campos `art_test`, `art_technique`, `tests_included`, `test_guids`,
  `coverage`, `validation_status`, `last_validated` para trazar qué atomic
  tests cubre cada regla.
- `docs/S1QL_tutorial.md`: guía de la sintaxis real de S1QL 2.0 (campos,
  operadores, escapado de backslash), en gran parte confirmada
  empíricamente pegando queries en la consola real.
- Metodología de pruebas en 6 fases antes de activar una regla en bloqueo
  real (`tests/README.md`), con simuladores inofensivos y evidencia de
  resultados por regla.
- `LICENSE` (AGPL-3.0-or-later), `CONTRIBUTING.md`, `SECURITY.md` y CI
  (`validate_rules.py` en cada push/PR).

### Cambiado
- **Formato de las reglas**, dos veces: de una pseudo-sintaxis STAR
  (`Rule / Severity / Category / Action / Condition`) que resultó no ser la
  real, a un formato intermedio (`.star`: cabecera de metadatos en
  comentarios + cuerpo S1QL 2.0 plano), y de ahí al formato actual — YAML
  con metadatos tipados y validables por JSON Schema, más un campo `query`
  de texto plano para el S1QL.
- **Estructura de carpetas**, dos veces: primero de nombres de táctica sin
  numerar a `rules/NN-tactica/` numeradas según el orden de kill chain de
  MITRE ATT&CK; después renumeradas de 14 a 15 tácticas cuando MITRE
  ATT&CK v19 (28 de abril de 2026) retiró Defense Evasion y la dividió en
  **Stealth** (hereda TA0005) y **Defense Impairment** (TA0112 nueva).
- **Nombres de archivo**: de un nombre descriptivo libre a
  `<técnica>[.<subtécnica>].<so>.<nombre-descriptivo>.yml`, validado contra
  `mitre.techniques[0].id` y el campo `os`.
- Migradas las técnicas T1562/T1562.001/T1562.006 a **T1685** (fusión) y
  T1562.003 a **T1690** (técnica separada) tras el split de ATT&CK v19.
- Todas las reglas: `license` de `"MIT"` (heredado, incorrecto) a
  `"AGPL-3.0-or-later"`, coherente con la licencia real del proyecto.
- Proyecto renombrado de `grayhats-sentinelone-star` a **GrayHats
  SentinelOne Detection Library**, de cara a su publicación como software
  libre.

### Corregido
- Bug recurrente en varias reglas: excluir por
  `src.process.publisher = "Microsoft Corporation"` en vez de por nombre de
  binario, lo que anulaba la detección real (`cmd.exe`/`powershell.exe`/
  `sc.exe`/`schtasks.exe` están firmados por Microsoft y son la vía de
  invocación más habitual, tanto legítima como maliciosa).
- Varios campos y operadores S1QL invocados incorrectamente por analogía
  con otras plataformas (`event.type` como `"Network Connection"`/
  `"DNS Query"` en vez de los reales `'IP Connect'`/`'DNS Resolved'`;
  escapado de backslash simple dentro de `matches` frente al doble en
  rutas literales), corregidos tras pruebas reales en consola.
- Dos reglas de la familia Potato para T1548.002 retiradas por estar ya
  cubiertas de forma nativa por el motor de comportamiento de SentinelOne.

### Eliminado
- Reglas de UAC bypass (`T1548.002`, ángulo registro y ángulo
  comportamiento) tras confirmar que el motor nativo de SentinelOne ya las
  cubre — mantenerlas solo añadía ruido de mantenimiento sin aportar
  detección adicional.
