# Limitaciones y defectos verificados

## Tres causas pendientes, cuatro reproducciones

No se cambió SQL, servicios, validaciones, RLS ni funcionalidades para hacer pasar la colección.

| Incidencia | Evidencia local | Consecuencia |
|---|---|---|
| Crear workspace adicional | POST /api/v2/workspaces declara 201, devuelve 404 RESOURCE_NOT_FOUND; SQLSTATE 42501 en INSERT ON CONFLICT RETURNING | La lectura de la fila durante el alta ocurre antes de tener membresía visible por RLS. El alta personal usa otro camino y funciona. No se eludió la política. |
| undetermined no admitido por SQL V2 | Evaluador/Pydantic permiten undetermined; CHECK app_findings_applicability_valid admite potential/confirmed/not_applicable | Fixture AND original termina en 503 NVD_PROCESSING_FAILED y run failed/PROCESSING_ERROR. Revisar undetermined sobre un hallazgo potential devuelve 409 INTEGRITY_CONFLICT; rollback comprobado. Son dos manifestaciones de la misma incompatibilidad. |
| Título truncado termina en espacio | La descripción original normalizada y cortada a 500 termina en espacio; viola app_findings_title_valid | Con variante OR y título original, POST análisis devuelve 503 y conserva historial failed sin hallazgos. |

`probe_known_issues.py` reproduce las cuatro observaciones. El perfil positivo cambia explícitamente a OR y título corto SIMULADOS para poder probar hallazgos/recomendaciones; no oculta ni resuelve estas incompatibilidades. En OpenAPI se mantiene el 201 contractual del POST workspace y se agrega su respuesta 404 observada. No hay ejemplo fabricado de una creación adicional exitosa.

## Herramientas de pruebas

Newman 6.2.3 se instaló solo como dependencia local de api-tests/v2, con package-lock. `npm audit` informó **19 entradas: 6 moderadas, 12 altas y 1 crítica**, incluidas cadenas transitivas de la herramienta. La actualización normal permitida no las eliminó; no se aplicaron downgrades ni overrides mayores sin validar compatibilidad. Ver [tooling-audit-summary.json](examples/tooling-audit-summary.json). No cargar colecciones de terceros no revisadas ni exponer este runner a servidores externos. No es una dependencia ni se copia a la imagen de la API; api-tests queda fuera del contexto Docker.

Este resultado no significa 19 vulnerabilidades nuevas del backend. Tampoco se declara seguridad completa de la herramienta. Si la política del equipo prohíbe esas dependencias, importar el JSON en una instalación de Postman aprobada en vez de instalar Newman; esa aplicación nativa no se probó aquí.

Se conserva el warning de Starlette/TestClient sobre httpx2 y el aviso de Node DEP0176 emitido por Newman. No se actualizó el runtime productivo para silenciarlos.

## Alcance de la evidencia

- 39 operaciones HTTP invocadas; 38 con respuesta positiva, una creación adicional bloqueada. Los errores esperados que pasan una aserción no equivalen a funcionalidades corregidas.
- 17 operaciones conservan response_model y 22 (V2 y health/ready) salidas sin modelo estricto. Los ejemplos no añaden validación de salida: debe revisarse eso como cambio funcional separado.
- No hay endpoints públicos de gestión de membresías ni lectura de auditoría. Las políticas/roles se comprueban en el SQL y regresión existente, no mediante rutas inventadas.
- NVD en vivo, todas las combinaciones de CVE, cuotas reales, navegador Swagger/Postman nativos, carga, móvil, backups/restore y despliegue productivo no se ejecutaron en esta misión. Se verificó HTTP 200 y contenido generado de docs/redoc/openapi; no una prueba visual de su UI.
- La colección está diseñada para fixtures en un servidor efímero identificado. En datos reales pueden faltar hallazgos y se omiten las operaciones dependientes si no hay finding_id. No se elige automáticamente un candidato CPE real.
- No se ejecutó ZAP, no se visitaron referencias ni objetivos de escaneo, no se aplicaron migraciones a bases persistentes.
- No hay refresh/revocación individual de JWT; cuotas de registro por proceso y protocolo HMAC con replay dentro de vigencia son límites heredados, sin cambios.
- La **ratificación global del modelo V2 sigue pendiente**. D-003 de Context aprueba el cómputo del dashboard, sin ratificar globalmente workspace/aplicaciones frente a dispositivos. No se modificó Context.
