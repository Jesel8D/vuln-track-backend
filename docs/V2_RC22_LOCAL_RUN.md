# Ejecutar RC2.2 aislada desde Windows

Desde PowerShell abrir `wsl -d Ubuntu-24.04`. En Ubuntu:

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-RC2.2/vuln-track-backend
.venv/bin/python -m scripts.v2_development status --profile rc2-catalog
```

Si el perfil está detenido:

```bash
.venv/bin/python -m scripts.v2_development up --profile rc2-catalog \
  --pg-port 55444 --api-port 8010 --web-port 5183 \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

Volumen dedicado `vulntrack_v2_rc2_catalog_pgdata`. [Interfaz](http://127.0.0.1:5183) · [Swagger](http://127.0.0.1:8010/docs)

En otra terminal de Ubuntu, desde el mismo Backend, cargar las fuentes solo si hace falta sincronizar. La copia de demostración se puede cargar sin Internet.

```bash
.venv/bin/python -m scripts.sync_cpe_catalog --mode fixture \
  --vendor cisco --product small_business_rv340_firmware
.venv/bin/python -m scripts.sync_cpe_catalog --mode live \
  --vendor cisco --product small_business_rv340_firmware --pages 1
```

La primera sincronización live y la carga fixture se realizaron en el perfil entregado. Para reanudar una sincronización incompleta, usar `--mode live --resume UUID --pages 1`, donde UUID es el identificador del recibo inicial. La revisión reproducible del flujo CVE debe elegir el catálogo fixture. Para una consulta oficial CVE, iniciar explícitamente el perfil propio en live y usar una identificación live. El operador puede guardar una clave opcional en `.local/rc2-catalog/nvd-api-key` con permisos 0600.

```bash
.venv/bin/python -m scripts.rc1_acceptance --profile rc2-catalog --phase create
.venv/bin/python -m scripts.test_rc1_recovery --profile rc2-catalog
```

El arnés valida que el perfil de pruebas y el restore utilicen puertos y volúmenes propios. El segundo comando reinicia RC2.2, prueba una copia en otro volumen, detiene la copia y deja ambos volúmenes disponibles. Los respaldos y credenciales de pruebas son privados.
