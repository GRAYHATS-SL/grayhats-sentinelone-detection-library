# Tutorial básico de S1QL 2.0

Guía rápida para escribir la parte de `Condition` de una regla STAR (el
campo `query` de los archivos `.yml` de este repo) en S1QL 2.0, la query language
real del editor de la consola de SentinelOne.

## Anatomía de una query

Toda query parte de tres filtros base, casi siempre presentes al principio:

```
dataSource.name = 'SentinelOne'
AND endpoint.os = 'windows'
AND event.type = 'Process Creation'
```

- **`dataSource.name`**: de qué fuente de datos vienen los eventos (el
  agente de SentinelOne, Cloud Funnel, etc.). Inclúyelo siempre: sin él, la
  query puede intentar evaluarse contra fuentes que no tienen los campos
  que usas (p. ej. `tgt.process.*` no existe en logs de firewall), lo que
  en el mejor caso no matchea nunca y en el peor da error.
- **`endpoint.os`**: `'windows'`, `'linux'` o `'macos'`. Acota la regla al
  sistema operativo donde tiene sentido — evita evaluarla en endpoints
  donde ni siquiera existen los binarios que buscas.
- **`event.type`**: qué tipo de evento estás mirando. **Valores reales
  confirmados pegando queries en la consola** (no adivinados): `'Process
  Creation'`, `'File Creation'`, `'File Modification'`, `'File Rename'`,
  `'Event Log'`, `'DNS Resolved'` (⚠️ no "DNS Query" — así se llamaba en
  nuestra primera versión y era incorrecto), `'IP Connect'` (⚠️ no "Network
  Connection" — mismo caso). `'Process Access'` sigue sin confirmar. Acepta
  lista: `event.type in ('File Creation', 'File Modification')`.

**Nuestras reglas actuales no incluyen `dataSource.name`/`endpoint.os`
todavía** — es una mejora pendiente, ver el aviso al final de este
documento.

## Los campos dependen del tipo de evento — no son universales

Esto costó varias iteraciones equivocadas, así que va primero: **`tgt.*` y
`src.*` no significan lo mismo en todos los `event.type`.** Antes de copiar
un patrón de una regla a otra, confirma que el tipo de evento coincide.

### `event.type = 'Process Creation'`

| Campo | Qué es |
|---|---|
| `tgt.process.name` | Nombre del proceso creado (el "hijo") |
| `tgt.process.cmdline` | Línea de comandos completa del proceso creado |
| `src.process.name` | Nombre del proceso que lo creó (el "padre") |
| `src.process.user` | Usuario bajo el que corre el proceso padre |
| `src.process.parent.name` | Nombre del **abuelo**: el proceso que creó al padre |
| `src.process.publisher` | Firmante del proceso padre — **evita excluir por este campo**, ver la nota de "buenas prácticas" más abajo |

### `event.type = 'IP Connect'` (conexiones de red — no "Network Connection")

| Campo | Qué es |
|---|---|
| `event.network.direction` | `'OUTGOING'` / `'INCOMING'` — **no** `tgt.network.direction` |
| `event.network.connectionStatus` | `'SUCCESS'` para filtrar solo conexiones establecidas (sin confirmar del todo) |
| `src.process.name` | El proceso que abre la conexión — en este tipo de evento **no existe un "tgt.process" útil**, solo hay un proceso relevante |
| `src.ip.address` | IP origen de la conexión |
| `dst.ip.address` | IP destino — **no** `tgt.network.ip.address` |
| `dst.port.number` | Puerto destino — **no** `tgt.network.port`. Soporta comparación numérica (`>`, `<`) y `in (...)` con números sin comillas |

**Dos limitaciones importantes confirmadas en un `IP Connect`:**
- **`tgt.process.cmdline` no está poblado de forma fiable.** Si necesitas
  filtrar por argumentos de línea de comandos (p. ej. `Invoke-WebRequest`,
  `-Method POST`), usa una regla sobre `event.type = 'Process Creation'` en
  su lugar, no intentes leer la cmdline desde el evento de red.
- **`dns.request` no está poblado.** La resolución DNS y la conexión IP son
  eventos distintos en este modelo — no puedes usar `dns.request` (ni para
  detectar "conexión sin DNS previo" ni como exclusión por dominio) dentro
  de una condición sobre `IP Connect`. Para excluir destinos legítimos, usa
  `dst.ip.address` en su lugar.

### `event.type = 'DNS Resolved'` (no "DNS Query")

| Campo | Qué es |
|---|---|
| `tgt.network.dns.request` | El hostname consultado |

### `event.type = 'File Modification'` / `'File Rename'` / `'File Creation'`

| Campo | Qué es |
|---|---|
| `tgt.file.path` | Ruta completa del archivo afectado |
| `tgt.file.extension` | Extensión del archivo, **sin el punto** (`"lockbit"`, no `".lockbit"`) |
| `src.process.name` | Proceso que modificó/creó/renombró el archivo |
| `src.process.user` | Usuario bajo el que corre ese proceso |

En general: `tgt.*` es "el objeto sobre el que ocurre el evento" (el proceso
que se crea, el archivo que se modifica) y `src.*` es "quién lo provoca" —
pero en eventos de red (`IP Connect`) solo hay un proceso relevante y va en
`src.process.*`, no hay un `tgt.process` útil.

## Operadores

| Operador | Qué hace | Ejemplo |
|---|---|---|
| `=` / `!=` | Igualdad exacta | `tgt.process.name = 'vssadmin.exe'` |
| `>` / `<` | Comparación numérica — confirmado sobre campos numéricos como `dst.port.number` | `dst.port.number > 1024` |
| `contains` | Substring (sensible a mayúsculas) | `tgt.file.path contains '.git/hooks'` |
| `contains:anycase` | Substring, insensible a mayúsculas | `tgt.process.name contains:anycase '7z'` |
| `in` | Pertenece a una lista (sensible a mayúsculas). Con campos numéricos, los valores van sin comillas | `dst.port.number in (3389, 8080, 8443)` |
| `in:anycase` | Pertenece a una lista, insensible a mayúsculas | `src.process.user in:anycase ('jenkins')` |
| `matches` | Regex (PCRE). Soporta flags inline como `(?i)`. **El escapado de backslash dentro de la regex es SIMPLE (`\.`), no doble** — distinto de los strings literales de rutas (ver más abajo) | `dst.ip.address matches '^(10\.\|192\.168\.)'` |
| `=*` / `!(campo=*)` | "Campo no vacío" / "campo vacío" | `!(tgt.network.dns.request=*)` — pero ver el aviso sobre `IP Connect` más arriba: en ese tipo de evento `dns.request` nunca está poblado, así que este check no discrimina nada ahí |
| `!(...)` | Negación — validado repetidamente en pruebas reales de consola, es el estilo usado en la mayoría de reglas de este repo | `!(src.process.user contains:anycase ('SYSTEM', 'NETWORK SERVICE'))` |
| `AND` / `OR` / `NOT` | También funcionan (confirmado: alguna regla probada con `NOT` sigue así tras la prueba), en mayúscula o minúscula. `!(...)` es simplemente el estilo que ha ido predominando a medida que se prueban más reglas — no hay evidencia de que `NOT` esté "roto" | — |

**`contains`, `contains:anycase` e `in`/`in:anycase` aceptan una lista
directamente** — evita encadenar muchos `OR`:

```
// En vez de esto:
tgt.process.name = "cmd.exe" OR tgt.process.name = "powershell.exe" OR tgt.process.name = "wscript.exe"

// Escribe esto:
tgt.process.name in ("cmd.exe", "powershell.exe", "wscript.exe")
```

**S1QL no soporta agregaciones ni pipes dentro del `query` de una regla
STAR** (confirmado): nada de `| group by`, `| count`, `estimate_distinct`,
etc. Si necesitas contar eventos por origen/destino en una ventana de
tiempo (p. ej. "más de 5 conexiones en 5 minutos", "un mismo origen contra
múltiples destinos"), esa lógica se hace en **Event Search / PowerQuery**
como consulta de threat hunting, no dentro de la condición de la regla. El
único mecanismo de umbral *dentro* de una regla STAR que hemos visto es el
campo opcional `trigger` del schema (`count > N within Xs`), y sigue sin
confirmar si el editor de la consola realmente lo acepta — ver
[`rules/12-command-and-control/T1071.001.win.c2-https-beaconing.yml`](../rules/12-command-and-control/T1071.001.win.c2-https-beaconing.yml).

### Comillas y escapado de backslash

Los ejemplos de consola usan indistintamente **comillas simples** (`'...'`)
y dobles (`"..."`) — ambas funcionan, confirmado en múltiples reglas ya
probadas. Mantén la que ya use el archivo que edites, no mezcles estilos
dentro de una misma regla.

Para **backslashes literales** (rutas de Windows, UNC), sigue haciendo
falta doblarlos: `'Z:\\'`, `'\\\\'` para un UNC. Pero **dentro de una regex
de `matches`, el backslash va simple**: `matches '^(10\.|192\.168\.)'`, no
`matches '^(10\\.|192\\.168\\.)'`. Es la única excepción a la regla de
doblar backslashes — confirmado en
[`rules/12-command-and-control/T1071.004.win.c2-dns-tunneling.yml`](../rules/12-command-and-control/T1071.004.win.c2-dns-tunneling.yml)
y [`rules/10-lateral-movement/T1021.001.win.rdp-outbound.yml`](../rules/10-lateral-movement/T1021.001.win.rdp-outbound.yml).

## Ejemplo paso a paso: construir la regla de `vssadmin`

Así se construyó [`rules/14-impact/T1490.win.vssadmin-delete-shadow-copies.yml`](../rules/14-impact/T1490.win.vssadmin-delete-shadow-copies.yml):

1. **¿Qué evento busco?** La creación de un proceso: `event.type = "Process Creation"`.
2. **¿Qué proceso es el sospechoso?** `vssadmin.exe` apareciendo en la línea de comandos del proceso creado: `tgt.process.cmdline contains:anycase "vssadmin.exe"`.
3. **¿Qué patrón de esa línea de comandos es malicioso?** Borrar o encoger las copias de sombra: agrupa las variantes con `OR` dentro de un paréntesis:
   ```
   AND (
       tgt.process.cmdline contains:anycase "delete shadows"
       OR tgt.process.cmdline contains:anycase "resize shadowstorage"
   )
   ```
4. **¿Qué quiero excluir para no generar ruido?** Los binarios de backup/RMM legítimos que sí llaman a vssadmin, por nombre del proceso padre:
   ```
   AND NOT (
       src.process.name = "wbengine.exe"
       OR src.process.name = "vdsldr.exe"
       OR src.process.name = "Veeam.Backup.Manager.exe"
   )
   ```
5. **Junta todo** y esa es la query completa del campo `query` del archivo `.yml`.

Para las siguientes reglas, sigue el mismo orden: evento → objeto sospechoso → patrón malicioso → exclusiones de ruido conocido.

## Buenas prácticas para este repo

- Empieza siempre por `dataSource.name`/`endpoint.os`/`event.type` (ver aviso pendiente abajo).
- Usa listas (`in`, `contains:anycase (...)`) en vez de encadenar `OR` — es más corto y más legible.
- Cuidado con condiciones demasiado amplias que anulan el valor de otra parte de la regla (ver la nota de `.dll` en [`rules/04-execution/T1204.002.win.office-child-process-suspicious-args.yml`](../rules/04-execution/T1204.002.win.office-child-process-suspicious-args.yml): un `contains ".dll"` sin acotar habría matcheado casi cualquier uso normal de `regsvr32.exe`/`rundll32.exe`).
- Documenta en el campo `notes` del archivo cualquier suposición sin confirmar (valores de `event.type` no verificados, campos que dependen de cómo el agente reporta cierto tipo de evento, etc.) — no lo des por hecho silenciosamente.
- Antes de activar, sigue el flujo de [`tests/README.md`](../tests/README.md).
- Cuando pegues una query en la consola y confirmes que no da error de sintaxis, marca `syntax_checked: true` en el archivo (campo opcional del schema). No significa que la regla esté en `Active` ni que hayas corrido las fases de `tests/README.md` — solo que la sintaxis es válida.

## Pendiente

- Ninguna regla incluye todavía `dataSource.name`/`endpoint.os` al principio de la query — es una mejora a aplicar en una pasada aparte sobre `rules/**/*.yml`.
- `event.type = 'Process Access'` (usada en `T1003.001.win.lsass-memory-dump.yml` para una versión anterior, ya migrada a un enfoque por `Process Creation`) sigue sin confirmar contra consola.
- Varias reglas de red (`win-c2-*`, `T1048.003.win.to-uncommon-ports-exfiltration.yml`) siguen sin `syntax_checked: true` — están escritas con los campos ya confirmados (`IP Connect`, `event.network.direction`, `dst.*`) pero no verificadas una a una todavía.

## Fuentes

- Ejemplos de la consola de SentinelOne y pruebas reales pegando queries (aportados directamente por el usuario — la fuente más fiable que tenemos, por encima de cualquier búsqueda pública).
- [j0shnan/S1QueryConverter](https://github.com/j0shnan/S1QueryConverter) — mapeo oficial de campos y operadores v1→v2.
- [zrnge/s1-power-queries](https://github.com/zrnge/s1-power-queries) — ejemplos reales de queries con listas en `contains:anycase`/`in`.
