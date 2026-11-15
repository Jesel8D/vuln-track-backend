# Fixtures NVD usados en estabilización

Fuente: [proveniencia original](../../tests/fixtures/README.md), capturada el 2026-11-08 America/Mexico_City, timestamps NVD 2026-11-09. No son datos actuales ni escaneos.

El CPE fijo verificado es `C817E5BA-62C1-41E7-A15C-FB851FEA761E`, firmware Cisco RV340 1.0.0.33. La colección compara UUID, binding completo y deprecated; no confirma por posición del primer candidato.

El perfil por defecto usa **el CVE original AND y su descripción larga**, sin sustituirlos por OR/título corto para esconder fallos. El caso CVE-2017-6784 requiere condiciones de hardware adicionales; applicability inicial undetermined es deliberado. Después de SQL007 y el recorte seguro de título, se persiste y revisa conservando las descripciones originales.

Las variantes OR/título corto siguen disponibles solo como escenarios explícitos de tests. La evidencia histórica de 6331564 registra cómo fallaban los casos originales antes de estabilizar; no se presenta esa evidencia como resultado actual.

Solo se sustituye el transporte NVD por MockTransport de origen/rutas fijos. Auth, API HTTP, PostgreSQL, RLS, transacciones y worker permanecen reales. El reloj de cuota externo se simula para no esperar; no prueba cuotas NVD live. El registro de runners usa cuota ampliada, mientras el desarrollo persistente mantiene la normal.

No se siguen referencias ni se consulta dispositivo alguno. El destino loopback de ejemplo se registra como inventario y se rechaza, sin solicitud HTTP ni escaneo ZAP. Los ejemplos publicados reemplazan IDs/fechas/usuarios y vacían tokens; los hashes dentro de esa representación sanitizada son ilustrativos, no permiten verificar un registro reconstruido. Los dumps privados y claves nunca se publican.
