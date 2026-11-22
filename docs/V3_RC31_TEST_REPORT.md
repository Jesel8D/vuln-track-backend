# Informe de pruebas RC3.1

Resultados del 22 de noviembre de 2026. Las bases de prueba de Backend fueron PostgreSQL desechables. Chromium usó datos de demostración en el perfil RC3.1. El modo CVE del piloto fue fixture.

| Verificación | Resultado |
|---|---|
| Backend, instalación existente | 788 pruebas y 151 comprobaciones SQL correctas |
| Backend, instalación nueva | 788 pruebas y 151 comprobaciones SQL correctas |
| Frontend | TypeScript, ESLint, 98 pruebas de Vitest y build correctos |
| Chromium | 13 pruebas completas y 1 prueba de reanudación después de reiniciar |
| Accesibilidad | Navegación de selectores con teclado y comprobaciones axe en pantallas de 375, 768, 1280 y 1440 px |
| OpenAPI y colección Postman | 69 operaciones, 104 peticiones de colección, 34 modelos de cuerpo y 80 ejemplos positivos validados |
| Newman, instalación existente | 109 peticiones y 397 aserciones correctas |
| Newman, instalación nueva | 106 peticiones y 382 aserciones correctas |
| Newman, perfil persistente | 52 peticiones y 195 aserciones correctas |

SHA-256 de OpenAPI: `db36a3c337f9ae36b014f327d5c61d9392aac6e8b40d066c6ac8e08587ceb1c8`. Pytest emitió una advertencia de dependencia en ambas rutas.

## Fuente externa y aislamiento

Se levantó una segunda instancia PostgreSQL desechable con un catálogo oficial pequeño. El login de lectura pudo consultar el catálogo. Las pruebas rechazaron una cuenta con más privilegios y comprobaron que el login limitado no podía modificar filas ni leer tablas privadas. Se simularon indisponibilidad, espera por lock, recuperación y metadatos CPE inconsistentes. El registro y la reidentificación guardaron evidencia e historial en la base local. La regresión de esquema comprueba RLS, constraints y preservación de revisiones.

## Recorridos en Chromium

Se comprobó la apertura sin búsqueda previa, el filtrado dependiente y la limpieza de selección, la referencia física Dell, el registro con componente Apache del piloto, y el flujo Cisco fixture con consulta CVE y revisión. También se probó el alta manual, el cambio de firmware, la caducidad de la identidad anterior, la reidentificación y la conservación del análisis anterior. El caso de Cisco verificó recarga, cierre de sesión y nuevo inicio de sesión.

Tras reiniciar RC3.1, los recuentos siguieron en 14 dispositivos, 10 identificaciones, 6 revisiones, 6 análisis y 15 registros de catálogo en el piloto de pruebas. Chromium volvió a comprobar el acceso del usuario existente a su CPE, análisis, revisión y recomendaciones.

## Validación pendiente

- Control manual en Edge. La herramienta terminó la sesión porque no pudo determinar la URL activa de Windows con suficiente confianza. Los recorridos arriba son automatizados. [Guion manual](V3_RC31_LOCAL_RUN.md)
- Catálogo completo de RC2.3. El servidor histórico sigue detenido. Quedan por medir el conteo actual, las búsquedas multifabricante y las latencias sobre esa fuente, después de recibir autorización y activar el rol limitado. [Activación](V3_RC31_CATALOG_ACCESS.md)
