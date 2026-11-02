# GrayHats SentinelOne Detection Library

Colección abierta de reglas STAR (Storyline Active Response) para
SentinelOne, gestionadas como código: cada regla es un archivo YAML
versionado, validado contra un JSON Schema y trazable a una técnica de
MITRE ATT&CK. El objetivo es que una regla se pueda leer, revisar en un
Pull Request y probar antes de activarla en producción, en vez de vivir
solo como configuración suelta dentro de la consola de SentinelOne.

> **Aviso:** este es un proyecto independiente de GrayHats. No está afiliado,
> patrocinado ni respaldado por SentinelOne, Inc. SentinelOne y los demás
> nombres de productos citados son marcas de sus respectivos propietarios y se
> mencionan solo para identificar la plataforma a la que se dirigen las reglas.

## Sobre este proyecto

Esta biblioteca es una iniciativa de GrayHats para contribuir a mejorar la
ciberseguridad de las empresas y organizaciones. Creemos que la detección de
amenazas mejora cuando se comparte: cada regla que se publica, se revisa y se
corrige ahorra trabajo a otros equipos de seguridad y eleva el nivel de
protección de todos. Por eso la publicamos como software libre y la
planteamos como un esfuerzo colectivo, no como un producto cerrado.

**Objetivo.** Cubrir con reglas de detección toda la cadena de ataque (la
*cyber kill chain*), desde el reconocimiento hasta el impacto, usando como
marco las tácticas y técnicas de [MITRE ATT&CK](https://attack.mitre.org/).
El proyecto se organiza siguiendo ese mismo orden: las reglas viven en
carpetas numeradas por táctica (`01-reconnaissance` … `15-impact`, ver
[Carpetas de `rules/`](#carpetas-de-rules-y-su-táctica-mitre-attck)), y cada
regla indica la plataforma a la que aplica (Windows, Linux o macOS) en el
campo `os` y en su nombre de archivo (`win`, `lnx`, `mac`). La cobertura
objetivo incluye las tres plataformas; hoy hay reglas de Windows y Linux, y
todavía ninguna de macOS (ver [Estado del proyecto](#estado-del-proyecto)).

**Enfoque: las primeras fases de la cadena.** Lo más interesante, y donde
creemos que esta biblioteca aporta más, son las reglas para las primeras fases
de la kill chain (reconocimiento, acceso inicial, ejecución, descubrimiento).
Son reglas que detectan actividad que un administrador de sistemas podría
realizar legítimamente en su trabajo diario, como ejecutar `whoami`, pero que
no es normal en un entorno determinado. Su valor está en la desviación respecto
a lo habitual, no en que el comportamiento sea malicioso en sí. Por eso
complementan, y no sustituyen, a las detecciones que el motor de SentinelOne
ya trae de serie para el comportamiento claramente malicioso, y por eso suelen
requerir ajuste: qué es anómalo depende de cada organización, así que conviene
medir primero el ruido en modo `Detect` y adaptar las exclusiones antes de
pasar a una acción de respuesta. Hoy la cobertura de estas fases es todavía
escasa (por ejemplo, `10-discovery` no tiene reglas), y es una de las áreas
donde más se agradecen aportaciones.

**Es un trabajo en curso, no terminado, y puede contener errores.** Las reglas
se siguen escribiendo, probando y corrigiendo de forma continua, y habrá fallos
de lógica, falsos positivos, falsos negativos y técnicas sin cubrir. La mejora
continua es parte del diseño: por eso cada regla declara su estado de
validación (`status`, `syntax_checked`, `validation_status`) y la sección
[Estado del proyecto](#estado-del-proyecto) dice con honestidad qué está
probado y qué no. Antes de activar cualquier regla en producción, pruébala en
tu propio entorno. **Si encuentras un error, las correcciones son muy
bienvenidas.**

**Pruebas y validación.** Para probar y validar las reglas usamos
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team): cuando
existe un *atomic test* para la técnica, la regla lo referencia (`art_test`,
`test_guids`) y se anota si ha disparado como se espera (`validation_status`,
`last_validated`). No todas las técnicas tienen un atomic test, y hoy solo una
parte de las reglas está mapeada y validada con él (ver
[Estado del proyecto](#estado-del-proyecto)). Por eso cualquier otra prueba
fiable y rigurosa es igualmente bienvenida: simuladores propios, otras
herramientas de emulación de adversarios, ejercicios de red team o evidencias
de producción. Si aportas una prueba, documenta cómo reproducirla y qué
resultado se esperaba (ver [`tests/README.md`](tests/README.md)), para que
otras personas puedan repetirla y verificarla.

**Idioma.** Los nombres de las reglas, de los archivos y los términos técnicos
(MITRE ATT&CK, S1QL, nombres de campos y de eventos) están en inglés, porque es
el idioma de la plataforma y del sector. Sin embargo, el idioma que se usa
mayoritariamente en el proyecto es el **español**: descripciones, notas de las
reglas, documentación y discusiones. Puedes contribuir en español o en inglés.

**Toda propuesta es bienvenida**: reglas nuevas, correcciones, exclusiones
para reducir falsos positivos, evasiones que hayas encontrado, mejoras de
documentación o simplemente una idea. Consulta [`CONTRIBUTING.md`](CONTRIBUTING.md)
para saber cómo aportar, y [`SECURITY.md`](SECURITY.md) si lo que has
encontrado conviene reportarlo en privado. ¡Gracias por sumarte!

## Licencia

Copyright (C) 2026 GrayHats. Este proyecto se publica bajo la
[GNU Affero General Public License v3.0 o posterior](LICENSE)
(`AGPL-3.0-or-later`). Todas las reglas del repositorio declaran esta misma
licencia en su campo `license`.

## Estado del proyecto

Este proyecto está en desarrollo activo. Ninguna regla ha sido promovida
todavía a `status: Active` en este repositorio — se van escribiendo,
validando y probando en `Draft` antes de decidir cuáles se activan en
producción. Fotografía actual (`python scripts/validate_rules.py` pasa en
verde sobre las 54):

| Métrica | Valor |
|---|---|
| Reglas totales | 54 |
| Por estado | 54 `Draft` |
| Con `syntax_checked: true` (sintaxis comprobada en consola) | 31 / 54 |
| Tácticas MITRE ATT&CK cubiertas | 11 / 15 |
| Por sistema operativo | 46 Windows · 8 Linux |
| Con test de Atomic Red Team asociado (`art_test: true`) | 13 / 54 |
| Validadas contra Atomic Red Team (`validation_status: validated`) | 6 / 54 |

`syntax_checked: true` indica que la sintaxis de la `query` se verificó en la
consola (fases 1-2 de [`tests/README.md`](tests/README.md)), no que la
regla esté validada de punta a punta contra un ataque real ni que esté ya
en `Active` — esa es una barra más alta y deliberadamente distinta, ver
[`tests/README.md`](tests/README.md) para las 6 fases completas.

## Estructura de carpetas

```
rules/                  # una regla por archivo .yml, agrupada por táctica MITRE ATT&CK
schemas/                # JSON Schema que define el formato válido de una regla
environments/           # account_id / site_id / URL de consola por entorno (dev, staging, prod)
scripts/                # validación y (a futuro) despliegue vía API de SentinelOne
docs/                   # documentación adicional (mapeo MITRE, guías internas)
tests/                  # pruebas automatizadas sobre el formato/lógica de las reglas
.github/workflows/      # CI: valida las reglas contra el schema en cada push/PR
```

| Carpeta | Para qué sirve |
|---|---|
| `rules/NN-tactica/` | Contiene las reglas ya escritas, una por archivo `.yml`. La subcarpeta identifica la táctica MITRE a la que pertenece la regla, numerada según el orden de la kill chain de MITRE ATT&CK (ver tabla más abajo). El listado completo de reglas está en [`rules/README.md`](rules/README.md). |
| `schemas/` | `star-rule.schema.json` define los campos obligatorios y sus tipos/valores permitidos. |
| `environments/` | Datos de conexión y scope (`account_id`, `site_id`, `console_url`) para cada entorno donde se pueden desplegar reglas. No contiene lógica de detección. |
| `scripts/` | `validate_rules.py` valida el formato de todas las reglas contra el schema. `c2c_beaconing_analyzer.py` es una herramienta de apoyo DFIR (ver [`rules/README.md`](rules/README.md#herramientas-complementarias-scripts)), con sus propias dependencias en `requirements-analysis.txt`. Aquí irá también `deploy_rules.py` cuando se automatice el despliegue vía API. |
| `docs/` | Documentación adicional: [`docs/S1QL_tutorial.md`](docs/S1QL_tutorial.md) explica cómo escribir la query de una regla desde cero. |
| `tests/` | Cómo probar una regla antes de activarla (simuladores seguros, test plans, evidencia de resultados). Ver [`tests/README.md`](tests/README.md). |
| `.github/workflows/` | Pipelines de CI. `validate.yml` ejecuta `validate_rules.py` en cada push y Pull Request a `main`. |

### Carpetas de `rules/` y su táctica MITRE ATT&CK

Numeradas según el orden de la kill chain de MITRE ATT&CK Enterprise **v19**
(28 abril 2026, 15 tácticas: Reconnaissance → Impact). El número **no** tiene
otro significado que ese orden.

| Carpeta | Táctica MITRE ATT&CK |
|---|---|
| `01-reconnaissance` | Reconnaissance |
| `02-resource-development` | Resource Development |
| `03-initial-access` | Initial Access |
| `04-execution` | Execution |
| `05-persistence` | Persistence |
| `06-privilege-escalation` | Privilege Escalation |
| `07-stealth` | Stealth |
| `08-defense-impairment` | Defense Impairment |
| `09-credential-access` | Credential Access |
| `10-discovery` | Discovery |
| `11-lateral-movement` | Lateral Movement |
| `12-collection` | Collection |
| `13-command-and-control` | Command and Control |
| `14-exfiltration` | Exfiltration |
| `15-impact` | Impact |

Si una regla no encaja claramente en ninguna, se guarda en la carpeta de la táctica primaria de MITRE y se referencian las técnicas secundarias en `mitre.secondary`.

> **Nota ATT&CK v19:** hasta el 28 de abril de 2026, Defense Evasion (TA0005)
> era una única táctica; v19 la retiró y la dividió en **Stealth** (hereda
> TA0005 — el adversario se esconde, las defensas siguen funcionando) y
> **Defense Impairment** (TA0112, nueva — el adversario rompe activamente las
> defensas: matar el EDR, borrar logs, desactivar el AV). De ahí que Enterprise
> pasara de 14 a 15 tácticas y las carpetas 08 en adelante se renumeraran.
> También se fusionaron T1562/T1562.001/T1562.006 en **T1685**, y T1562.003
> se separó como técnica propia, **T1690**. Detalle completo en
> [`rules/README.md`](rules/README.md).

## Formato de nombre de archivo

```
<técnica>[.<subtécnica>].<so>.<nombre-descriptivo>.yml
```

- `<técnica>[.<subtécnica>]`: el `id` de `mitre.techniques[0]` (la técnica
  **primaria**; si una regla cubre varias técnicas de la misma táctica, se usa
  la primera del array). Ejemplos: `T1490`, `T1071.001`.
- `<so>`: `win` / `lnx` / `mac`, según el campo `os`.
- `<nombre-descriptivo>`: kebab-case, lo que antes era el nombre completo del archivo.

Ejemplo: [`rules/15-impact/T1490.win.vssadmin-delete-shadow-copies.yml`](rules/15-impact/T1490.win.vssadmin-delete-shadow-copies.yml).

El validador (`scripts/validate_rules.py`) comprueba que la técnica y el SO
del nombre de archivo coincidan con `mitre.techniques[0].id` y `os` del
contenido — no solo que la carpeta coincida con `mitre.tactic`.

## Formato de una regla

Cada archivo es un YAML con metadatos estructurados (validables contra
[`schemas/star-rule.schema.json`](schemas/star-rule.schema.json)) y un campo
`query` que contiene la query completa en **S1QL 2.0**, tal cual se pega en
el editor de condición de la consola:

```yaml
name: "<nombre de la regla>"
author: "GrayHats Detection Team"
license: "AGPL-3.0-or-later"
os: windows | linux | macos
mitre:
  tactic: "<una de las 15 tácticas de la tabla de arriba>"
  techniques:
    - id: T####
      name: "<nombre de la técnica>"
  secondary:               # opcional: técnicas de OTRA táctica (p. ej. el vector de entrega)
    - id: T####
      name: "<nombre>"
      tactic: "<otra táctica>"
severity: Low | Medium | High | Critical
category: "<categoría de consola, ej. Ransomware, Phishing, Credential Access>"
action: "<acción real, ej. Detect | Kill | KillAndQuarantine | DisconnectNetwork>"
action_description: >
  <breve explicación en humano de qué hace la acción>
scope: global | account | site | group
status: Draft | Active | Disabled
expiration: Permanent | YYYY-MM-DD
tags: [tag1, tag2]
notes:
  - >
    <supuestos, limitaciones conocidas, cosas pendientes de verificar>
query: |
  event.type = "..."
  AND ...
```

`query` usa un bloque literal YAML (`|`) para preservar el S1QL exactamente
como se escribe — no lo reformatees ni lo metas en una sola línea.

Campos obligatorios: `name`, `author`, `license`, `os`, `mitre.tactic`,
`mitre.techniques`, `severity`, `category`, `action`, `scope`, `status`,
`expiration`, `query`, `validation_status`. El validador también comprueba
que `mitre.tactic` coincida con la carpeta en la que vive el archivo.

`validation_status` (`not_tested` | `validated` | `failed`) es obligatorio
en toda regla, tenga o no ya un atomic test de Atomic Red Team mapeado:
`not_tested` es el valor por defecto de cualquier regla nueva, tanto si
aún no se ha identificado un atomic test concreto como si ya hay uno
mapeado pero no se ha ejecutado todavía (fase 5 de
[`tests/README.md`](tests/README.md)).

Campos opcionales: `tags`, `notes`, `trigger`, `power_query_hunting`,
`syntax_checked`, `mitre.secondary`, `mitre.tactics` (cuando el comportamiento cruza
varias tácticas), y el resto de campos de integración con **Atomic Red
Team** (`art_test`, `art_technique`, `tests_included`, `test_guids`,
`coverage`, `last_validated`) — solo tienen sentido cuando ya hay un
atomic test concreto identificado para la regla. Ver
[`rules/07-stealth/`](rules/07-stealth/) para ejemplos reales.

Ver ejemplo real en [`rules/15-impact/T1490.win.vssadmin-delete-shadow-copies.yml`](rules/15-impact/T1490.win.vssadmin-delete-shadow-copies.yml). Si es la primera vez que escribes una query en S1QL 2.0, empieza por [`docs/S1QL_tutorial.md`](docs/S1QL_tutorial.md).

> **Nota histórica:** este repo pasó por dos formatos previos antes de
> asentarse en este: una pseudo-sintaxis STAR (`Rule "..." / Severity "..." /
> Category "..." / Action "..." / Condition`) que resultó no ser la real, y
> después un `.star` con cabecera de metadatos en comentarios + cuerpo S1QL
> 2.0 plano. Este último funcionaba pero mezclaba metadatos y query en texto
> libre sin validación estructurada real. El formato YAML actual separa
> ambas cosas: metadatos tipados y validables con JSON Schema, query como
> bloque de texto plano intacto.
>
> Los operadores de S1QL 2.0 están confirmados con fuentes públicas (no
> adivinados): el mapeo v1→v2 de campos y operadores del conversor
> [j0shnan/S1QueryConverter](https://github.com/j0shnan/S1QueryConverter),
> y ejemplos reales de queries con listas en `contains:anycase`/`in` en
> [zrnge/s1-power-queries](https://github.com/zrnge/s1-power-queries). Aun
> así, algunos valores exactos de `event.type` (p. ej. para eventos de
> acceso a proceso) siguen sin confirmar — ver las `notes` de cada regla.

## Cómo aplicar una regla en la consola de SentinelOne

Los archivos `.yml` de este repo son la fuente de verdad legible, pero SentinelOne no tiene un importador de YAML para STAR — se crea la regla desde la consola mapeando cada campo:

1. En la consola, ir a **Visibility → STAR Rules → New STAR Rule** (o desde una query en Deep Visibility, **Create STAR Rule from Query**).
2. Rellenar **Name** con el campo `name`, y **Description** con `action_description` y `notes` si aplica.
3. Seleccionar **Severity** igual al campo `severity` del archivo, y **Category** igual a `category`.
4. Definir el **Scope** (Account / Site / Group / Global) según el campo `scope`, eligiendo el `account_id`/`site_id` del entorno correspondiente en `environments/<entorno>.yml`.
5. Pegar el campo `query` tal cual en el editor de condición de la regla — es S1QL 2.0 completo, listo para pegar.
6. Elegir la **Automatic Response Action** igual al campo `action` del archivo (p. ej. `KillAndQuarantine` → "Kill and Quarantine").
7. Configurar la **Expiration** (Permanent / Temporary + fecha) según `expiration`.
8. Guardar la regla como **Draft** primero si el campo `status` del archivo es `Draft` — nunca lanzar directo a `Active` en producción sin antes revisar falsos positivos.
9. Cuando el campo `status` pase a `Active` en el repo (tras validarla en producción sin ruido), activarla también en consola y actualizar el archivo.

## Flujo de trabajo para añadir y validar reglas

1. **Crear una rama** para la regla o lote de reglas nuevas.
2. **Escribir el archivo** en `rules/NN-tactica/<tecnica>.<so>.<nombre-descriptivo>.yml` siguiendo el schema y el formato de nombre. Empezar siempre en `status: Draft`.
3. **Validar localmente**:
   ```bash
   pip install -r requirements.txt
   python scripts/validate_rules.py
   ```
   Corrige cualquier `[ERROR]` que reporte (campos faltantes/inválidos según el schema, o `mitre.tactic` que no coincide con la carpeta).
4. **Actualiza [`rules/README.md`](rules/README.md)** añadiendo la fila de la regla nueva en la tabla de su carpeta.
5. **Revisión por otra persona** antes de mergear — especialmente la lógica de `query` y las exclusiones (falsos positivos, riesgo de bypass), como se hizo con la regla de `vssadmin`.
6. **Merge a `main`** solo cuando la regla esté validada y revisada.
7. **Aplicar manualmente en consola** siguiendo la sección anterior, como `Draft`, y probarla siguiendo las fases de [`tests/README.md`](tests/README.md) antes de dejarla en observación.
8. Cuando se confirme que no genera falsos positivos y que la acción de respuesta hace lo esperado (fases 4 y 5 de `tests/README.md`), **activar en consola** y actualizar `status: Active` en el archivo del repo, en un commit aparte. Documenta la evidencia en `tests/results/<nombre-regla>.md`.
9. Si una regla deja de ser útil o se sustituye, no se borra: se pasa a `status: Disabled` y se desactiva también en consola, dejando el archivo como histórico.
