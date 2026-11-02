# Política de seguridad

Este repositorio publica **reglas de detección**, no software ejecutable con
superficie de ataque propia — pero sí hay dos tipos de reporte que
agradecemos que se hagan de forma privada en vez de vía issue público:

## Qué reportar en privado

- **Evasión de una regla**: si encuentras una forma de ejecutar la técnica
  que una regla dice detectar sin que dispare (más allá de las limitaciones
  ya documentadas en el campo `notes` de la propia regla, que son
  conocidas y no hace falta reportar).
- **Exposición de datos sensibles**: si alguna regla, script o ejemplo
  contiene, por error, datos de un cliente real (IPs, hostnames, nombres de
  organización) en vez de datos ficticios de ejemplo.
- **Vulnerabilidad en las herramientas del repo**: `scripts/validate_rules.py`
  o `scripts/c2c_beaconing_analyzer.py` (por ejemplo, si procesar un archivo
  de entrada malicioso permite algo más que un error controlado).

## Cómo reportarlo

Envía un correo a **csirt@grayhats.com** con:
- Qué regla(s) o script(s) están afectados.
- Pasos para reproducir el problema.
- Impacto que consideras que tiene.

Confirmaremos la recepción en un plazo razonable. Al ser un proyecto
mantenido por voluntarios en su tiempo libre, no hay un SLA formal, pero los
reportes de evasión/exposición de datos se priorizan sobre cualquier otra
tarea.

## Qué NO es un problema de seguridad

- Que una regla en `status: Draft` o con `syntax_checked: false` no funcione todavía
  como se espera — eso es un bug de calidad normal, repórtalo como issue o
  Pull Request siguiendo [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Falsos positivos esperables ya documentados en las `notes` de la regla.

## Alcance

Esta política cubre el contenido de este repositorio. No cubre la
plataforma SentinelOne en sí — para reportar una vulnerabilidad del propio
producto, contacta directamente con SentinelOne.
