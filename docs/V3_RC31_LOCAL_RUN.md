# Arranque y guion de RC3.1

En PowerShell, abre Ubuntu con `wsl -d Ubuntu-24.04`. El perfil aislado usa `vulntrack_v2_rc3_catalog31_pgdata`.

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-RC3.1/vuln-track-backend
bash scripts/setup_rc23_dependencies.sh
.venv/bin/python -m scripts.v2_development status --profile rc3-catalog31
```

Si está detenido, inicia el piloto con el rango local comprobado. Revisa puertos y subred si se cambia de equipo.

```bash
export VULNTRACK_RC31_DOCKER_SUBNET=10.254.248.32/28
.venv/bin/python -m scripts.v2_development up --profile rc3-catalog31 \
  --pg-port 55452 --api-port 8018 --web-port 5191 \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

## Guion de navegador

1. Entra con una cuenta de prueba y abre Dispositivos → Registrar dispositivo. Selecciona Router, escribe fabricante y modelo físicos, e indica ubicación. Para un servidor de prueba, abre las referencias de hardware y busca Dell y R740.
2. Elige Firmware y selecciona el catálogo oficial sincronizado. Abre el selector de fabricante sin escribir, verifica que presenta opciones, filtra por `cis` y selecciona `cisco`.
3. Abre Producto, filtra por RV340 y selecciona `small_business_rv340_firmware`. Abre Versión y selecciona `1.0.0.33`.
4. Abre CPE exacto. Revisa el UUID, la fecha y la procedencia. Confirma que corresponde al equipo observado, escribe el motivo y guarda. Antes de guardar, se puede limpiar fabricante para comprobar que desaparecen los campos dependientes.
5. Cierra sesión y recarga. Vuelve a iniciar sesión y abre el mismo dispositivo. Revisa que mantiene el CPE y la identificación.
6. Registra un segundo router con el mismo producto y versión, usando el catálogo fixture y una etiqueta diferente. Selecciona **Consultar CVE**. Revisa el hallazgo fixture `CVE-2017-6784` y guarda una evaluación y recomendación de prueba. Comprueba que aparecen en el historial.
7. Edita la versión a `1.0.1.16`. Confirma el cambio y guarda. El análisis anterior sigue visible y la consulta nueva queda bloqueada. Usa **Buscar nueva identidad**, repite los desplegables en fixture y confirma el nuevo candidato.
8. Registra otro equipo con **Registrar sin identificación CPE**. Deja la versión vacía y comprueba que queda pendiente.
9. Prueba fuente oficial en un servidor de muestra con Dell como referencia física y Apache como componente. El estado del piloto muestra 13 registros oficiales. La prueba multifabricante del catálogo completo se reserva para cuando el estado confirme una fuente externa activa.
10. Usa otra sesión para comprobar que la URL de un dispositivo ajeno no devuelve sus datos. Para los casos de roles y dos editores, usa las cuentas y pruebas aisladas de la regresión.

[Piloto RC3.1](http://127.0.0.1:5191) · [Swagger](http://127.0.0.1:8018/docs) · [Activación de la fuente](V3_RC31_CATALOG_ACCESS.md)
