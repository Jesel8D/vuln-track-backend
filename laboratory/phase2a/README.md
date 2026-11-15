# Laboratorio local de transporte y red

Ejecutar desde Backend con dependencias bloqueadas y Docker Desktop Linux activo:

```bash
.venv/bin/python -m scripts.test_v2_security_lab
```

El runner construye una imagen con contexto explícito de siete archivos de
código/laboratorio, sin .env, .local, bases, credenciales Git ni archivos del
host. La imagen base tiene digest fijo; IDNA está fijado a 3.20 como en el lock.
Los paquetes apt no tienen snapshot binario fijado. El ID final se conserva en
la evidencia privada; certificados y claves son sintéticos y se generan nuevos
por ejecución. No se instala ZAP ni se conecta PostgreSQL.

Topología: fixture y worker comparten un namespace `--network none`. Solo existe
loopback; no se publican puertos ni se conectan redes externas. Alias locales:
93.184.216.10/11 y 2606:4700:ffff::10 para HTTPS; 10.77.0.10, loopback y
169.254.169.254 para canarios. Son servicios simulados dentro de ese namespace,
no conexiones a los titulares públicos de esas direcciones. El resolutor solo
devuelve fixtures de memoria; no consulta DNS externo.

El helper efímero de confianza usa NET_ADMIN exclusivamente dentro de ese
namespace para instalar OUTPUT DROP IPv4/IPv6 con excepciones a TLS del fixture
y respuestas establecidas. Termina antes de iniciar las pruebas. El worker
no tiene NET_ADMIN, NET_RAW ni otras capacidades, no usa privileged/host network
y no puede modificar esa política. El fixture TLS, administrado por el runner,
usa UID 0 sin capacidades para leer una clave sintética que el worker no puede
leer; no es el futuro contenedor executor.

Se prueba TLS, SNI/Host, IPv4/IPv6, certificado inválido/expirado/no confiable,
límites, cancelación y el flujo de un desafío aleatorio. Durante el intercambio
se prohíbe getaddrinfo para detectar cualquier nueva resolución silenciosa.
Luego se salta deliberadamente la política Python para probar denegaciones de
red TCP/UDP. Los canarios escuchan y deben recibir cero conexiones/datagramas.

El worker usa UID 65532, CapDrop ALL, no-new-privileges, raíz de solo lectura,
tmpfs limitado noexec/nosuid/nodev, CPU 0.5, memoria/swap 128 MiB, PIDs 32,
FDs 64 y logs rotados. Las configuraciones se cotejan con /proc y cgroup v2.
Una sonda independiente de 32 MiB verifica OOM real y termina; no se ejerce
presión ilimitada sobre la PC. No hay mounts del usuario, volúmenes de la
aplicación, docker.sock o secretos de aplicación.

El runner usa plazos de construcción/operación y limpieza por etiqueta aleatoria
propia, sin eliminar volúmenes. Los resultados nuevos invalidan cualquier JSON
de éxito anterior antes de empezar. Evidencia: api-tests/v2/.artifacts/phase2a/
network-lab-results.json. Los logs privados de fallos no se confunden con ese
resultado final ni se versionan. La primera línea del protocolo privado contiene
el cuerpo del desafío y el padre la consume sin imprimirla.

Límites: no demuestra salida selectiva a Internet, un DNS real autorizado,
firewall Windows, un scheduler de trabajos ni aislamiento de datos entre
ejecuciones reales. El administrador del host/daemon permanece fuera del límite
de confianza. El namespace network-none prueba un laboratorio sin salida; una
futura plataforma con salida pública necesita otras pruebas y aprobación.

Ver [informe técnico](../../docs/V2_SECURITY_ANALYSIS_PHASE2A.md) y
[checklist independiente](../../docs/V2_ZAP_READINESS_CHECKLIST.md).
