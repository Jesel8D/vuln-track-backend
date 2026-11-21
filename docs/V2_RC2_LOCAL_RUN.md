# Ejecutar RC2 en Windows y WSL2

Desde PowerShell abrir Ubuntu:

```powershell
wsl -d Ubuntu-24.04
```

Dentro de Ubuntu:

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-RC2/vuln-track-backend
.venv/bin/python -m scripts.v2_development status --profile rc2
```

Si RC2 está detenida, iniciar en primer plano:

```bash
.venv/bin/python -m scripts.v2_development up --profile rc2 \
  --pg-port 55440 --api-port 8006 --web-port 5179 \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

Web http://127.0.0.1:5179 y Swagger http://127.0.0.1:8006/docs.
Los puertos guardados del perfil prevalecen al reiniciar. Usar el volumen
`vulntrack_v2_rc2_pgdata`. Mantener aparte el volumen personal y el de RC1.
Los worktrees están en `/home/mz/VulnTrack-RC2`. No realizar restore sobre
el volumen RC2, RC1 o development.

Si se prepara otro checkout coordinado con los hashes del manifiesto:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.lock -r api-tests/v2/requirements-api.lock
.venv/bin/pip install --no-deps -e .
npm ci --prefix api-tests/v2 --ignore-scripts
(cd ../vuln-track-frontend && npm ci)
```

El cambio de modo se realiza deteniendo únicamente el perfil RC2 desde su
worktree. Usar `--nvd-mode live` en un arranque posterior si se desea ese modo.
El historial conserva su origen. La clave opcional solo se lee desde el
archivo privado descrito en [NVD live](V2_RC2_NVD_LIVE.md).

```bash
.venv/bin/python -m scripts.v2_development stop --profile rc2
.venv/bin/python -m scripts.v2_development backup --profile rc2
```

El backup inicia PostgreSQL propio si estaba detenido. Conservar dump y
manifiesto juntos bajo .local/rc2, en privado. Para restaurar en otro volumen:

```bash
read -r -p 'Ruta absoluta del dump RC2: ' rc2_archive
rc2_restore="rc2-restore-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
.venv/bin/python -m scripts.v2_development restore --profile "$rc2_restore" \
  --pg-port 55441 --api-port 8007 --web-port 5180 --archive "$rc2_archive"
.venv/bin/python -m scripts.v2_development up --profile "$rc2_restore" \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

La copia necesita puertos libres, perfil nuevo y volumen ausente. Tras revisar
login, inventario, historial y aislamiento, detener solo ese perfil. El JWT
del origen no es válido en el restore. La contraseña de la cuenta sí lo es.
El dump contiene hashes de usuarios y material privado de contexto. Conservarlo
fuera de Git y usar una copia externa cifrada si se necesita recuperación ante
pérdida de disco.

La prueba de navegador crea cuentas ficticias en RC2 y deja su acceso privado
en `.local/rc2/demo-access.json`. El guion manual puede usar una cuenta nueva.
Reinicio/restauración automatizados:

```bash
.venv/bin/python -m scripts.rc1_acceptance --profile rc2 --phase create
.venv/bin/python -m scripts.test_rc1_recovery --profile rc2
```

Estos comandos verifican propiedad y modo fixture. El segundo para/reinicia
solo RC2 y detiene la copia tras la prueba, conservando ambos volúmenes.
