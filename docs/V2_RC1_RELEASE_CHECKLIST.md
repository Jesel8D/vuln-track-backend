# RC1 — checklist técnico de revisión local

**IMPLEMENTADO CON LIMITACIONES.** Comprobaciones de esta misión, no aprobación
de producción. Consultar [informe](V2_RC1_INTEGRATION_REPORT.md),
[matriz](V2_RC1_REQUIREMENTS_MATRIX.md) y [limitaciones](V2_RC1_KNOWN_LIMITATIONS.md).

- [x] Verificar bases remotas y ancestros; Postman histórico ya incorporado.
- [x] Mantener los cuatro repositorios personales, main/rudi y MVP-B sin cambios.
- [x] Crear worktrees Backend/Frontend RC1; Database exacta sin cambios reales ni rama innecesaria.
- [x] Instalar locks existentes sin modificarlos y validar pip check.
- [x] RC1 con perfil, volumen, nombres, puertos y claves propios; development protegido.
- [x] Bootstrap limpio y actualización simulada, catálogo/roles mínimos/FORCE RLS y migraciones verificadas.
- [x] Ejecutar 755 pytest por ruta existing/new, SQL adversarial y laboratorios 2B/2C.
- [x] Ejecutar validación OpenAPI/Postman y Newman por ambas rutas y guardia persistente.
- [x] Ejecutar Frontend unitarias/componentes, TypeScript, ESLint y build después de las correcciones.
- [x] Navegador A/C/D/E y UX 375/768/1280/1440 con datos persistentes y fixture visible.
- [x] Revisar hallazgo manteniendo undetermined; recomendación manual sin afirmar reparación.
- [x] Comprobar cuentas/IDs/roles/workspaces y reutilización de conexiones sin fuga.
- [x] Reiniciar RC1 y comprobar conservación exacta más navegador B.
- [x] Backup privado/checksum/Git-ignore; restore en OTRO volumen nuevo, JWT renovado y navegador B.
- [x] Mantener verify 503, egreso público bloqueado y Baseline disabled; cero escaneos.
- [x] Preparar dataset ficticio y guion de 10–15 minutos sin depender de servicios externos.
- [x] Documentar V1 dispositivos frente a V2 aplicaciones y móvil pendiente, sin arquitectura nueva.

La publicación y los hashes finales se verifican **después** de este checklist y
quedan en el manifiesto/informe exportado de entrega. No se usa un hash ficticio
del propio commit dentro de su contenido. No se publican `.local`, dumps,
credenciales, respuestas Newman privadas, trazas ni contextos de fallo.

Requisitos humanos/operativos que siguen abiertos:

- [ ] Ratificación conjunta de Jesel y Rudi del alcance académico definitivo.
- [ ] Aprobación de entrega final por los revisores.
- [ ] Ventana separada y autorizada si se desea actualizar la instalación habitual.
- [ ] Endurecimiento y operación de producción, backups externos cifrados y recuperación ante pérdida de disco.
- [ ] Plataforma operativa y autorización posterior para egreso/verificación remota.
- [ ] Criterios independientes previos a cualquier ZAP; no pertenece al GO de esta RC1.

**GO técnico únicamente para revisión académica local controlada del flujo V2**
cuando el manifiesto de entrega confirme todas las ejecuciones verdes y hashes
remotos. **NO-GO** para producción, escaneo externo, sustitución automática del
MVP original o declaración de entrega final aprobada.
