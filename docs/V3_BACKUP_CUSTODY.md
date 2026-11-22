# Custodia del respaldo cifrado

La copia completa existente está en `F:\VulnTrack-Respaldos\RC24\full-rc23`. Su archivo cifrado mide 216 402 769 bytes y su SHA-256 es `138bf7980231039f8259af8449f211ffc91a4cb8c51893eb2e6061a540691d87`. El TAR público y su manifiesto están en `nvd-20261120`. C: y F: comparten SSD. La copia en un medio independiente queda pendiente de un destino autorizado.

## Procedimiento para el custodio

1. Confirma la autorización del medio, su ubicación y las personas con acceso. Usa `Get-Partition -DriveLetter F,<letra>` y `Get-Disk` para comprobar que el número de disco es distinto. Valida `Get-Volume` y deja margen para el resguardo.
2. Verifica que la ruta de destino esté ausente y no sea un enlace ni una carpeta de otra copia. Revisa su ACL o el control equivalente en el destino.
3. En WSL, verifica el respaldo con GnuPG y el manifiesto. La clave original se protege por separado.

```bash
.venv/bin/python -m scripts.rc24_backup verify \
  --directory /mnt/f/VulnTrack-Respaldos/RC24/full-rc23 \
  --key-file /ruta/privada/llave
```

4. Crea un directorio de entrega nuevo. Copia `database.dump.gpg` y `manifest.json`. Si también custodias la edición oficial, usa otro subdirectorio y copia `dictionary.tar.gz` y su manifiesto. `Copy-Item -LiteralPath` permite especificar cada origen. Comprueba que cada archivo de destino aún esté ausente. Conserva los originales.
5. Ejecuta `Get-FileHash -Algorithm SHA256 -LiteralPath <archivo>` sobre cada origen y copia. Compara también el digest con el manifiesto. Registra fecha, volumen, tamaño, digest, resultado y custodio. Mantén la llave en custodia aparte del respaldo.
6. Ensaya la recuperación cifrada sobre un destino nuevo. Usa el preflight para decidir entre una restauración persistente y el ensayo RAM. Desarrolla un calendario de verificación y rotación acordado por el equipo.

La restauración persistente completa sigue condicionada al margen físico de C: y un perfil nuevo. El piloto RC3 admite el mismo formato de respaldo cifrado con una llave propia mediante `scripts.rc24_backup backup --profile rc3`. [Arranque](V3_LOCAL_RUN.md) · [Pruebas](V3_TEST_REPORT.md)
