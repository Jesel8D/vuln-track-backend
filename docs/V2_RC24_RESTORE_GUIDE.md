# Recuperación verificable de RC2.4

## Verificar el respaldo cifrado

En Ubuntu 24.04, desde `/home/mz/VulnTrack-RC2.4/vuln-track-backend`, usa el directorio que contiene el manifiesto y la clave custodiada por separado. GnuPG debe estar instalado. En la estación usada, la clave se encuentra en un archivo WSL con permisos `0600`.

```bash
bash scripts/setup_rc23_dependencies.sh
backup='/mnt/f/VulnTrack-Respaldos/RC24/full-rc23'
key='/ruta/privada/llave'
.venv/bin/python -m scripts.rc24_backup verify --directory "$backup" --key-file "$key"
```

El archivo cifrado consumió **216 402 769 bytes**. El verificador compara fuentes SQL, formato, tamaño y digest. GnuPG comprueba la autenticidad antes de crear la base de destino. Un fallo deja el archivo de origen disponible para diagnóstico.

## Ensayo completo sin disco activo en F:

```bash
.venv/bin/python -m scripts.rc24_restore_drill --directory "$backup" --key-file "$key"
```

El ensayo reserva memoria según el tamaño del respaldo, con un máximo de 7 GiB para el volumen y una reserva adicional para PostgreSQL y el host. Exige al menos 2,5 GB libres en C:, Docker y soporte de `tmpfs,noswap`. Crea un volumen nuevo y un contenedor sin red ni puertos TCP. Restaura en una transacción y comprueba conteos y políticas. Detener el contenedor descarta los datos temporales. El respaldo sigue disponible en F:. La verificación de RC2.4 se hizo comparando una copia RAM del origen detenido y un segundo volumen RAM limpio. [Datos del ensayo](V2_RC24_TEST_REPORT.md) · [Semántica de tmpfs de Docker](https://docs.docker.com/engine/storage/tmpfs/)

## Restauración persistente

Usa la carpeta de trabajo de RC2.4 y un perfil `rc2-catalog24` sin volumen inicial. Antes de reservar almacenamiento, confirma dónde se encuentra el VHDX de Docker y compara el espacio físico con el presupuesto del manifiesto. La orden se bloquea si no hay margen suficiente o el perfil ya tiene un volumen. Conserva un perfil existente y realiza el ensayo RAM si necesitas verificar otra copia.

```bash
export VULNTRACK_RC24_DOCKER_SUBNET=10.254.248.0/28
.venv/bin/python -m scripts.rc24_backup restore --directory "$backup" --key-file "$key"
```

Este comando crea los roles esperados, restaura los objetos y datos, aplica la migración aditiva RC2.4 y vuelve a comprobar el esquema. Un rol de conexión y un secreto JWT nuevos aíslan la sesión de la instalación de origen. La clave de contexto PostgreSQL se recupera con los datos de la instalación.

## Reconstrucción del catálogo

El TAR conservado contiene el diccionario público. Valida la edición fijada y su manifiesto con el modo offline.

```bash
edition='/mnt/f/VulnTrack-Respaldos/RC24/nvd-20261120'
.venv/bin/python -m scripts.import_cpe_feed stage \
  --archive "$edition/dictionary.tar.gz" --edition "$edition/manifest.json"
```

El modo `stage` valida el archivo completo y emite el preflight. En este equipo marcó `full_safe: false`. Cuando el perfil de destino tenga margen suficiente para la carga completa, usa `import` con los mismos argumentos. El SHA-256 se verifica antes de escribir y los checkpoints se guardan por digest. La cuarentena de la edición conocida se ejecuta con `.venv/bin/python -m scripts.rc24_catalog_audit --archive "$edition/dictionary.tar.gz"` después de recuperar su recibo completo. Para los datos privados aplica la restauración del archivo PostgreSQL.

[Respaldo y custodia](V2_RC24_BACKUP_STRATEGY.md) · [Almacenamiento](V2_RC24_STORAGE_REPORT.md)
