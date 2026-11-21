# Limitaciones y decisiones de RC2

RC2 es una candidata técnica experimental. El acuerdo de Jesel y Rudi sobre
alcance académico, workspaces, evaluación y entrega definitiva sigue pendiente.
Se preserva la aprobación individual histórica de Jesel y D-001/D-002.

- Los activos V1 siguen bajo propiedad individual. RC2 agrega dispositivos en
  V2 y no importa datos automáticamente. Un cliente móvil futuro usaría la API
  autenticada de dispositivos. La app móvil está fuera de esta misión.
- La identificación es manual. La versión desconocida queda como null y el CPE
  necesita producto, componente y versión verificables. Esta RC2 permite cambiar el estado. La
  edición de datos observados, incluida una versión conocida después del alta, queda pendiente.
  La pertenencia de una plataforma adicional a un equipo real se verifica
  fuera de VulnTrack.
- Los presupuestos de NVD limitan la cobertura. Las consultas de aplicaciones y
  dispositivos muestran la procedencia por ejecución y la cobertura. Dashboard
  conserva recuentos de aplicaciones filtrables por fuente. Los resultados de
  dispositivos se consultan en su ficha. La interfaz mantiene el agregado legado
  cuando se ejecuta sin configuración de modo, por compatibilidad.
- El análisis V2 ejecuta una página acotada por solicitud y guarda estado
  persistente transaccional. Una interrupción de la consulta de dispositivo
  se muestra fallida tras el plazo de recuperación y se finaliza al pedir una
  nueva consulta. No se reenvía automáticamente el trabajo interrumpido.
- Roles y RLS se ejercitan con PostgreSQL. La interfaz no administra invitaciones
  o membresías. La cuota NVD es por proceso y el perfil local usa un proceso.
- Las pruebas de navegador miden Chromium y axe en los anchos indicados. No
  equivalen a certificación universal de accesibilidad. Sesión JWT en memoria,
  recarga requiere login y logout no revoca individualmente el token servidor.
- El laboratorio existente conserva sus límites. ZAP, verificación remota,
  escaneo de dispositivos/redes y egreso del ejecutor permanecen bloqueados.
  El catálogo NVD de origen fijo no es un ejecutor de tráfico para un destino.
- La alerta de stdout se mitigó en código y con el ensayo de recuperación.
  La repetición de CodeQL necesita una instalación del CLI.
- Los resultados de integración y cobertura no prueban aplicabilidad de un CVE
  a un equipo real. No se certifica un despliegue de producción.
