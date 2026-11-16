# Laboratorio de egreso Fase 2C

```bash
export DATABASE_V2_PATH=/home/mz/VulnTrack-security-phase2b/vuln-track-database
.venv/bin/python -m scripts.test_v2_egress_lab
```

Ejecutar desde Backend con sus dependencias bloqueadas. Crea tres redes internas
dual-stack, worker, gateway obligatorio, autoridad y fixtures propios; usa una
base tmpfs NUEVA mediante el broker externo. El worker no recibe credenciales de
DB/API/control. Los filtros se instalan únicamente en namespaces propios.
No se contactan sitios públicos, servicios internos reales ni la base personal.

El gateway acepta solo UUID de operación y un GET HTTPS acotado, sin CONNECT,
túneles ni destinos del usuario. Los permisos son exclusivamente de laboratorio.
La API operativa conserva verify=503 y ZAP no se instala ni ejecuta.

La evidencia final aparece solo tras completar pruebas y limpieza en
`api-tests/v2/.artifacts/phase2c/egress-lab-results.json`. Los logs de fallos no
equivalen a un resultado aprobado. La limpieza verifica etiqueta/nonce; no elimina
recursos ajenos ni volúmenes. Las imágenes y cachés de construcción se conservan.

[Arquitectura, diagrama, amenaza y límites](../../docs/V2_PHASE2C_EGRESS_SECURITY.md).
[Resultados y conteos](../../docs/V2_PHASE2C_LAB_RESULTS.md).
**Egreso público BLOQUEADO, incluso si todas las pruebas del laboratorio pasan.**
