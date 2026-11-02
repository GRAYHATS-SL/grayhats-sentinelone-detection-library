# Contribuir

Gracias por el interés en aportar reglas STAR de SentinelOne a este repositorio.

## Antes de empezar

- Lee [`README.md`](README.md) para el formato de archivo y de regla, y
  [`docs/S1QL_tutorial.md`](docs/S1QL_tutorial.md) si es tu primera vez
  escribiendo una query en S1QL 2.0.
- Revisa [`rules/README.md`](rules/README.md) para no duplicar una regla que
  ya exista para la misma técnica.
- Instala las dependencias del validador:
  ```bash
  pip install -r requirements.txt
  ```

## Flujo para añadir o modificar una regla

1. **Crea una rama** para la regla o lote de reglas.
2. **Escribe el archivo** en `rules/NN-tactica/<tecnica>.<so>.<nombre-descriptivo>.yml`
   siguiendo el schema (`schemas/star-rule.schema.json`) y el formato de
   nombre documentado en el README. Empieza siempre en `status: Draft` y
   `validation_status: not_tested` (obligatorio en toda regla, aunque
   todavía no tenga un atomic test de Atomic Red Team mapeado).
3. **Valida localmente** antes de abrir el PR:
   ```bash
   python scripts/validate_rules.py
   ```
   Corrige cualquier `[ERROR]` que reporte (campos faltantes/inválidos según
   el schema, `mitre.tactic` que no coincide con la carpeta, o el nombre de
   archivo que no coincide con la técnica/SO del contenido).
4. **Actualiza [`rules/README.md`](rules/README.md)** añadiendo la fila de
   la regla nueva en la tabla de su carpeta. Un objetivo en 1-2 frases, no
   una copia del `query`.
5. **Abre el Pull Request.** El CI corre `validate_rules.py` automáticamente;
   un PR con el validador en rojo no se revisa hasta que esté en verde.
6. **Revisión**: además del formato, se revisa la lógica de la `query` y las
   exclusiones — el bug más repetido en este repo ha sido excluir por
   `publisher = "Microsoft Corporation"`, que anula la detección de
   `cmd.exe`/`powershell.exe` (firmados por Microsoft y la vía de invocación
   más habitual, tanto legítima como maliciosa). Excluye siempre por nombre
   de binario/proceso conocido, no por publisher.
7. Tras el merge, la regla se aplica manualmente en la consola de
   SentinelOne (no hay despliegue automático) siguiendo la sección
   correspondiente del README, y se prueba según las fases de
   [`tests/README.md`](tests/README.md) antes de pasar a `Active`.

## Qué documentar en `notes`

Cualquier suposición sin confirmar (valores de `event.type` no verificados,
campos que dependen de cómo el agente reporta cierto evento, limitaciones
conocidas de falsos positivos/negativos) va en el campo `notes` de la
regla — no lo des por hecho silenciosamente. Es preferible una regla con
notas honestas sobre sus límites que una que aparente estar más probada de
lo que está.

## Reportar problemas de seguridad

Si encuentras una forma de evadir una de estas reglas o un fallo que
pudiera exponer datos sensibles, sigue [`SECURITY.md`](SECURITY.md) en vez
de abrir un issue público.

## Licencia

Al contribuir, aceptas que tu aportación se publique bajo los mismos
términos que el resto del proyecto: [AGPL-3.0-or-later](LICENSE).
