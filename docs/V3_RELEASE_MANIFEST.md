# Manifiesto RC3

| Repositorio | Commit base RC2.4 | Rama RC3 |
|---|---|---|
| Backend | `ca565c12f8f717f1b4c17e669ebb718a9e82fc9e` | `feat/v3-device-revisions` |
| Frontend | `71ab9654137f273aba9886ba8d6884cd7e99d2f1` | `feat/v3-device-editing-web` |
| Database | `54f681c9c2e9fdcea296bb062b63f6c25fa6c975` | `feat/v3-device-history-database` |
| Context | `651aa7b9dfd15e0b03f4540f4821f3ba93ab9a7f` | Referencia conservada |

La migración coordinada es SQL014 y `v2_0007_device_revisions`. El manifiesto de Backend identifica el hash de Database y el SHA-256 de la fuente. OpenAPI y la colección Postman mantienen las formas anteriores y añaden las cuatro operaciones RC3. El informe A–U registra los hashes publicados.

| Área | Estado |
|---|---|
| Edición, generaciones CPE, historial y control de concurrencia | IMPLEMENTADO Y PROBADO |
| Piloto RC3 y validaciones automáticas | IMPLEMENTADO Y PROBADO |
| Reconstrucción operativa de un catálogo completo en esta instalación | IMPLEMENTADO CON LIMITACIONES. El smoke test RC3 usa una muestra del catálogo. |
| Segunda copia cifrada en medio independiente | PENDIENTE de destino autorizado |
| Restauración completa persistente | BLOQUEADO por espacio físico |
| Aceptación académica | PENDIENTE de Jesel y Rudi |

[Contrato](V3_DEVICE_REVISION_CONTRACT.md) · [Pruebas](V3_TEST_REPORT.md) · [Custodia](V3_BACKUP_CUSTODY.md)
