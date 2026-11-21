# Manifiesto técnico RC2

Fecha local de revisión: 21 de noviembre de 2026. La candidata experimental
está preparada para revisión técnica local. La aprobación académica y de
producción requieren decisiones y validaciones posteriores.

| Repositorio | Base RC1 comprobada | Referencia de RC2 |
|---|---|---|
| Backend | 4453ae0d9b25de361947113f7c61c1b4797385ab | feat/v2-rc2-device-inventory-nvd. Commit funcional a24f9723682696204e0e3b151b1e5e0edb8ddd2d. El commit que contiene este manifiesto agrega solo documentación de entrega |
| Frontend | 4674cbcd9f46ad0e9e587b0db630b9f51a990a86 | feat/v2-rc2-device-inventory-web, a2ec5f026726b5f9ae915453e266116aa0f883fb |
| Database | a562e638dfe5b7e8d07eec0e8046e6998f8a2802 | feat/v2-rc2-device-inventory-database, 4fae50e8ed92fa1a5325e5cb00c5d497f639e234 |
| Context | 651aa7b9dfd15e0b03f4540f4821f3ba93ab9a7f | docs/mvp-context-consolidation conservada |

El archivo de entrega local identifica el HEAD completo de Backend y los hashes
que devuelve GitHub después de publicar. La revisión de base usa las cuatro
referencias de la copia RC1 recuperada. Las ramas personales y RC1 mantienen sus
bases. El SQL009 empaquetado coincide byte a byte con el de Database.
OpenAPI SHA-256 `20ce3e3b4f89c297387e15ab5aa95e795802642871d2bc78a13421f92d69af4b`.

- [Arquitectura y compatibilidad](V2_RC2_ARCHITECTURE.md)
- [Inventario, API y guion de demostración](V2_RC2_DEVICE_INVENTORY.md)
- [NVD en vivo y fixture](V2_RC2_NVD_LIVE.md)
- [Corrección de la alerta CodeQL](V2_RC2_CODEQL_FIX.md)
- [Resultados y restauración](V2_RC2_TEST_REPORT.md)
- [Ejecución y recuperación](V2_RC2_LOCAL_RUN.md)
- [Limitaciones, alcance y decisiones](V2_RC2_LIMITATIONS.md)

Perfil local rc2 con web5179, API8006, PostgreSQL55440 y su volumen propio.
El modo de demostración es fixture y el smoke live fue independiente y acotado.
CVE-2017-6784 del fixture sigue indeterminado después de la revisión.
ZAP, verificación remota de destinos, escaneo de redes y egreso público del
ejecutor están bloqueados. CodeQL queda pendiente de reejecución y el probe
que originó el hallazgo ya fue corregido y probado en el recorrido legado.
Los logs brutos, dumps, credenciales y configuraciones son privados.
