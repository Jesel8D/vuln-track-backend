# Compatibilidad inspeccionada: MVP-B y V2

Inspección Git real, 2026-11-13; las páginas públicas anteriores no se usaron para
elegir una base. Todos los remotos oficiales permitieron clone/fetch; API GitHub
de PR devolvió listas vacías para los cuatro repositorios en esta inspección.

| Repositorio | MVP-B | V2 rudi | Ascendencia |
|---|---|---|---|
| Backend | `7126a161040062b6f0f992c65faf8db07d326464` | `c1feca473fe8c553f0eac26d71a8651aaa0f2f26` | MVP-B es ancestro; 17 commits posteriores. |
| Database | `e39dd357b28e33912ad062efc813244c62f3eb4b` | `6fa928105d9157fbd78b66a17f8b86f9353857e0` | Divergen: 2 exclusivos MVP-B, 4 V2; base común `b493fd1`. |
| Frontend | `7ef0d451c7e92cda947115b5ace2970e424e6233` | `6cbdb0bc7424635d8d594467b413c303f91aa75a` | MVP-B es ancestro; 62 commits posteriores. |
| Context | `caa7ef13b0e2b24848991e32b3c0ee3fc59139c7` (consolidación) | `05195760ab8c08e6b74a3ad6ae01268a4e9d4386` | Referencias documentales independientes, sin merge en esta misión. |

Backend conserva V1 `578f74a`, V1.1 `8546b48`, V1.2 `3d23a1a` y V1.3 `2cb124d`
en su ascendencia. Su main sigue `b5e71f2`. No se reconstruyó el proyecto.

MVP-A/B gestiona dispositivos/activos con propiedad individual, identificación CPE,
consultas CVE y evidencia/revisión. V2 añade tablas separadas para aplicaciones web,
targets, tecnologías, workspaces/membresías, análisis/hallazgos/recomendaciones y
auditoría. Backend rudi tiene esas rutas `/api/v2`, directorio firmado y contexto
HMAC transaccional. Frontend rudi usa V2 como interfaz principal y conserva archivos
MVP como antecedente; sus rutas privadas actuales no exponen el inventario MVP.
No se añade un selector de dominio ni se elimina esa diferencia de alcance.

Database rudi conserva SQL001/002 de V1, pero no los bootstrap MVP-A/B de la otra
línea. No se fusionan ramas divergentes: Alembic backend0002/0003/0004 incorpora las
extensiones heredadas y se comprueba su coexistencia con SQL004/005 V2 en ambas
secuencias de instalación. La nueva SQL006 solo crea un rol/grants opt-in; no crea
otra tabla de usuarios ni sustituye políticas.

Estado verificado en esta entrega: registro/login/me, workspace propio, aplicaciones,
estados vacíos y aislamiento integrado. La suite histórica verifica regresión MVP
con fixtures NVD. La presencia de rutas V2 NVD/recomendaciones no equivale a haber
certificado todas sus transiciones o exhaustividad de NVD en esta misión.
ZAP es una vista con botón deshabilitado, no un ejecutor operativo.

Los E2E `web.spec.ts` y `z-cve.spec.ts` corresponden al contrato/rutas de Frontend
MVP-B. Se conservan intactos; el nuevo perfil explícito `v2-registration` ejecuta
`registration.spec.ts` contra React/FastAPI/PostgreSQL V2 reales. No se presentan
las pruebas antiguas de navegador como pruebas V2 ejecutadas.
