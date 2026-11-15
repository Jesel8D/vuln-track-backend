# Laboratorio Fase 2B — DNS, HTTPS y evidencia duradera

Desde Backend, con las dependencias bloqueadas instaladas y Docker Linux activo:

```bash
.venv/bin/python -m scripts.test_v2_security_lab --phase2b
```

Reutiliza el transporte, la imagen fijada y los controles del
[laboratorio de Fase 2A](../phase2a/README.md). La lista explícita de archivos de
construcción incluye el resolutor controlado, los fixtures DNS y estas pruebas;
no incorpora el árbol del host, secretos ni bases personales.

Un namespace `network none` contiene únicamente loopback y alias locales.
DNS TCP escucha en 10.77.0.53 y fd00:77::53; HTTPS usa alias locales con apariencia
pública. No se consulta un DNS externo ni se contacta a sus titulares públicos.
Un helper efímero NET_ADMIN aplica denegación OUTPUT por defecto IPv4/IPv6 dentro
de ese namespace. Solo permite DNS TCP al fixture y HTTPS a las IP autorizadas.
El worker usa UID 65532, capacidades cero y raíz de solo lectura, sin credenciales
de API/PostgreSQL, docker.sock o archivos del usuario. No cambia el firewall del
host Windows, WSL2 ni Docker Desktop.

El broker de laboratorio vive fuera del worker y crea PostgreSQL tmpfs propio.
Emite un desafío mediante FastAPI y el rol API, comprueba que `verify` devuelve
503 sin DNS, reclama un único intento con el rol de laboratorio y persiste el
resultado DNS/HTTPS. Incluso una coincidencia correcta termina como
`failed/LABORATORY_MATCH_ONLY`, nunca como control de dominio verificado.

La ejecución de entrega pasó 45 comprobaciones: las 27 anteriores repetidas y
18 adicionales, incluyendo DNS TCP IPv4/IPv6, CNAME, rebinding, cancelación,
límites, canarios, consumo SQL y persistencia de procedencia. Las pruebas de red
saltan deliberadamente la política Python para comprobar la segunda barrera.
Los contenedores propios se limpian por etiqueta aleatoria; no se borran volúmenes
ajenos. La evidencia privada queda ignorada en
`api-tests/v2/.artifacts/phase2b/network-lab-results.json`.

Este resultado prueba el laboratorio sin rutas externas. **El egreso público
selectivo continúa PENDIENTE; la verificación remota y ZAP siguen BLOQUEADOS.**
No certifica producción, un resolver operativo autenticado ni aislamiento frente
al administrador del host/daemon. Véanse el
[modelo y límites](../../docs/V2_SECURITY_ANALYSIS_PHASE2B.md) y el
[checklist](../../docs/V2_ZAP_READINESS_CHECKLIST.md).
