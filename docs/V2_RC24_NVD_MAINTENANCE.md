# Mantenimiento incremental del catálogo

La sincronización se ordena explícitamente desde un perfil RC2.4. El límite de cinco páginas por operación y el filtro por fabricante acotan las solicitudes. El origen HTTPS de la API de productos es fijo. El modo fixture evita llamadas externas durante las regresiones. Un intervalo requiere ambos extremos con zona horaria, en orden creciente y dentro de 120 días. [API de productos NVD](https://nvd.nist.gov/developers/products) · [Políticas de la API NVD](https://nvd.nist.gov/developers/start-here)

```bash
.venv/bin/python -m scripts.sync_cpe_catalog --mode live \
  --vendor cisco --product small_business_rv340_firmware \
  --modified-from '2021-04-26T11:29:09.037+00:00' \
  --modified-through '2021-04-26T11:31:09.037+00:00' --pages 1
```

Conserva el ID del recibo. `--resume ID` reutiliza filtros, intervalo y offset. El recibo bloquea el avance hasta el `retry_after` registrado, incluso si se inicia otro proceso. El cliente conserva un presupuesto independiente, interpreta `Retry-After` y evita ráfagas. Cada página guarda cambios, UUID nuevos, deprecaciones y descartes por razón. Si NVD cambia el total a mitad de ventana, revisa el recibo y repite el alcance acotado. Se recomienda registrar intervalos terminados y revisar un solapamiento breve en cambios recientes.

La deprecación actualiza la referencia pública. El detalle de un dispositivo puede advertir la deprecación y mostrar su fecha a partir del UUID y modo ya confirmados. El modelo, versión observada, identificación y consultas previas permanecen como en el momento de revisión. Los cambios en evidencia se registran mediante confirmación humana.

Una sincronización de catálogo consulta productos. El flujo CVE conserva su procedencia y presupuesto propios. El sistema requiere una operación explícita para obtener otra edición del feed.

Se ejecutó la ventana anterior dos veces en el piloto. NVD devolvió cuatro filas en ambas. La primera creó cuatro UUID. La segunda revalidó esas cuatro filas, con cero novedades, cambios, deprecaciones y descartes.
