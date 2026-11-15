# Límites actuales y correcciones V2

Las incidencias observadas en 6331564 se corrigieron en feat/v2-stabilization y SQL007:

- POST workspace adicional ya devuelve 201, admite replay/concurrencia y crea owner sin alterar RLS. Se retiraron las operaciones INSERT que exigían visibilidad prematura; un savepoint maneja UUID duplicado conservando el contexto transaccional.
- El CHECK V2 incorpora undetermined y retiene confirmed histórico; análisis AND original y revisión undetermined pasan. No se modifican filas históricas ni los guards de evidencia.
- FastAPI genera un título de presentación de hasta 500, recortando espacio final y avisando TITLE_TRUNCATED. La descripción original se conserva en evidence; el CVE capturado completo ya no provoca 503.

El antiguo [known-issues.json](examples/known-issues.json) es evidencia histórica de la rama base. El nuevo probe ejecuta regresiones positivas, carreras, aislamiento, revisión y conflicto obsoleto. La corrección no añade endpoints ni cambia contratos Pydantic.

Límites conservados:

- 22 salidas sin modelo estricto; sus ejemplos no sustituyen validación futura de salida.
- Descripciones/evidencia están sujetas al presupuesto de tamaño heredado: si se supera, EVIDENCE_BUDGET_REACHED/truncated informa la omisión. El título es un resumen deliberado, no el registro completo. No se amplió almacenamiento sin límites.
- No hay CRUD público de membresías/invitaciones ni lectura de auditoría; los eventos se escriben internamente. ZAP sigue sin endpoint habilitado, sin escaneos.
- NVD live, datos actuales generales, cargas, todos los navegadores, móvil y preparación de producción no se certifican. Los fixtures están fechados y son públicos, no objetivos escaneados.
- Registro y cuotas por proceso; sin recuperación/cambio de contraseña autoservicio, refresh/revocación individual, ni nonce HMAC de un solo uso.
- Newman conserva 10 entradas audit (5 altas/5 moderadas), tras 19 iniciales y eliminación del crítico; [detalle](../../docs/V2_NEWMAN_DEPENDENCIES.md). No es dependencia productiva y solo debe ejecutar esta colección revisada en loopback.
- La prueba persistent-contract de la colección usa tmpfs para comprobar omisiones; la retención real se prueba con test_v2_persistence y un volumen aparte. Ninguna suite temporal apunta al volumen development.
- La ratificación global de V2 permanece pendiente. D-003 del dashboard no ratifica toda la arquitectura.
