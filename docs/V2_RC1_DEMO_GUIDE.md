# RC1 — demostración manual de 10–15 minutos

**IMPLEMENTADO CON LIMITACIONES.** Demostración local reproducible con datos
ficticios y capturas NVD, para revisión de Jesel/Rudi. No es un escaneo ni prueba
de vulnerabilidad de un destino real. Preparar RC1 según
[ejecución local](V2_RC1_LOCAL_RUN.md), conservar el aviso de fixture visible y no
abrir enlaces externos de NVD/URL durante la presentación.

## Preparación privada

Abrir http://127.0.0.1:5177. Swagger está en http://127.0.0.1:8004/docs. La cuenta
principal y secundaria de la aceptación están exclusivamente en
`/home/mz/VulnTrack-rc1/vuln-track-backend/.local/rc1/demo-access.json`.
Consultar `primary` localmente, sin proyectar, publicar ni copiar su contraseña al
reporte. No hay contraseña de demo compartida en Git. También se puede crear una
cuenta nueva con contraseña privada desde **Crear cuenta**.

El dataset ya preparado incluye **DEMO RC1 - Portal de laboratorio**, descripción
FICTICIO, URL `https://example.com/rc1-demo` como inventario, tecnología manual
`small_business_rv340_firmware`, fabricante `cisco`, versión `1.0.0.33`, y CPE:

```text
cpe:2.3:o:cisco:small_business_rv340_firmware:1.0.0.33:*:*:*:*:*:*:*
```

La captura CPE usa el ID `C817E5BA-62C1-41E7-A15C-FB851FEA761E`. La captura CVE
es **CVE-2017-6784**, conservada con su AND original y condiciones de hardware.
Consultar el fixture no confirma que example.com utilice ese firmware. Se eligió
este caso para enseñar el límite **undetermined**, no para fabricar una
vulnerabilidad web. La medida manual es:

> DEMO: revisar el aviso capturado y las condiciones AND; no concluir vulnerabilidad en un sistema real.

## Guion (13 minutos orientativos)

| Tiempo | Acción manual | Resultado que explicar |
|---|---|---|
| 0:00–1:00 | Presentar problema y aviso de fixture | Inventario, identidad de producto y revisión de evidencia; NVD no descubre tecnologías ni escanea la URL |
| 1:00–2:30 | Crear cuenta normal nueva y hacer login | GET de identidad, workspace personal y rol owner; sin privilegios globales. Usar nombre único y contraseña privada; esperar Retry-After si hay cuota |
| 2:30–4:00 | Dashboard vacío → Registrar aplicación | Nombre `DEMO RC1 - Portal de laboratorio`, descripción FICTICIO; añadir URL de referencia. No solicitarla ni declararla como sitio propio real |
| 4:00–5:00 | Agregar tecnología manual | Producto y versión anteriores. Se registra una declaración de inventario, no descubrimiento automático |
| 5:00–6:30 | Buscar `RV340`, elegir candidato y pulsar Confirmar | Mostrar fabricante, producto, versión y CPE. La acción explícita es parte de la evidencia |
| 6:30–8:00 | Pulsar Consultar CVE en NVD y observar estado/progreso | Worker real, análisis persistente con datos capturados; no tráfico NVD live. Si termina rápido, mostrar el estado completado guardado |
| 8:00–9:30 | Abrir resultados e inspeccionar CVE-2017-6784 | Explicar condiciones AND/hardware. Elegir revisión que conserve Indeterminado, guardar motivo; no marcar confirmado |
| 9:30–10:30 | Abrir Recomendaciones y guardar medida manual | Texto anterior, pendiente; no confundir recomendación con mitigación realizada |
| 10:30–11:30 | Historial → Dashboard | Mostrar ejecución, revisión y recuentos reales; después de revisar puede haber cero abiertos aunque el CVE siga en el historial |
| 11:30–12:30 | Análisis de seguridad | Declaración ≠ prueba técnica; desafíos/revocación/caducidad del dataset preparado. ZAP Baseline disabled; verificación remota bloqueada |
| 12:30–13:00 | Logout/login y volver al historial | Persistencia. Explicar que recargar exige login porque el JWT vive en memoria |

Para una presentación de 10 minutos, usar la cuenta ya preparada y mostrar sus
datos; enseñar el formulario de alta sin repetir todo. Para 15 minutos, usar el
recorrido nuevo y cerrar con una segunda cuenta para mostrar aislamiento. No
mutar roles con herramientas de desarrollador: no concede permisos en SQL/API.

La aceptación automatizada ya completó este flujo, dos usuarios, caducidad real,
error/reintento, reinicio completo y restore separado. No hace falta ejecutar
esas operaciones durante la exposición. Si se desea demostrar reinicio en vivo,
reservar tiempo adicional y usar únicamente `--profile rc1` según la guía local.

## Repetibilidad y resultados esperados

Las cuentas de aceptación y sus aplicaciones son ficticias. Repetir
`scripts.rc1_acceptance --phase create` genera nuevas cuentas/dataset y archiva
privadamente el acceso anterior; no borra datos existentes. No ejecutar ese
comando si se quiere conservar exactamente el acceso que se está mostrando.

En el workspace principal preparado hay una aplicación y una ejecución. El
hallazgo permanece `undetermined`, estado `reviewed`, recomendación `pending`.
Se añadieron destinos de seguridad con declaración vigente/expirada y desafío
revocado/expirado; estos estados no habilitan ZAP ni representan control de
dominio. Los totales de todo el volumen incluyen ensayos anteriores y no deben
usarse como si fueran los del workspace activo.

Si un resultado difiere, detener la explicación y revisar API/historial y logs
locales. No inventar métricas, cambiar el fixture a OR, alterar reloj/RLS o
habilitar una función bloqueada para completar el guion.
