# Mitigación de la alerta CodeQL

Regla informada en la auditoría previa CodeQL 2.27.4
`py/clear-text-logging-sensitive-data`, ubicación histórica
`scripts/phase2a_upgrade_probe.py:85`.

La exposición se confirmó en código. El único consumidor localizado,
`scripts/test_v2_upgrade.py`, iniciaba un hijo por cada versión y capturaba
stdout para transferir estado. El objeto original incluía las contraseñas
sintéticas de ambas cuentas. El token Bearer se retiraba antes del print.
Los secretos de conexión, JWT y HMAC se pasaban al hijo por entorno y no eran
campos de la respuesta original. La captura normal reducía el alcance a un
protocolo privado, pero ejecutar el probe con salida capturada por CI o shell
podía salvar la contraseña en un registro.

El proceso padre ahora retiene las credenciales. El proceso hijo recibe stdin
privado y devuelve solo workspace, aplicación, destino, versión y un indicador
de alta secundaria. El padre valida la forma exacta y reconstruye localmente la
segunda identidad. Al fallar el hijo comunica un error genérico y descarta su
stderr. No se necesita archivo temporal nuevo. El protocolo continúa funcionando
entre las versiones legadas. El ensayo de upgrade/rollback ejecutado en RC2
comprobó registro, login, aislamiento, lectura después de reinicio y restauración
en otro volumen, con las instalaciones personales preservadas.

Estado de la alerta: **hallazgo confirmado y mitigado en código**. No se encontró
CodeQL en PATH de WSL ni de Windows durante la revisión. No se afirma una
reanálisis limpio. La reejecución de CodeQL queda pendiente de un CLI disponible.
