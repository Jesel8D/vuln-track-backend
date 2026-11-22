# Ejecutar el piloto RC3 en WSL2

En PowerShell abre Ubuntu con `wsl -d Ubuntu-24.04`. El piloto usa PostgreSQL local en un volumen independiente y una muestra pública leída del piloto RC2.4 en una transacción de solo lectura. La captura fixture para la segunda versión está incluida en las pruebas.

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-RC3/vuln-track-backend
bash scripts/setup_rc23_dependencies.sh
.venv/bin/python -m scripts.v2_development status --profile rc3
```

Para iniciar el piloto detenido, conserva la subred verificada localmente. Si el equipo cambia, verifica antes el espacio y las subredes.

```bash
export VULNTRACK_RC3_DOCKER_SUBNET=10.254.248.16/28
.venv/bin/python -m scripts.v2_development up --profile rc3 \
  --pg-port 55450 --api-port 8016 --web-port 5189 \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

El volumen se llama `vulntrack_v2_rc3_pgdata`. La prueba de navegador se ejecuta con `.venv/bin/python -m scripts.rc1_acceptance --profile rc3 --phase create` y se puede comprobar la persistencia con `--phase resume`. Usa cuentas sintéticas.

[Piloto](http://127.0.0.1:5189) · [Swagger](http://127.0.0.1:8016/docs)
