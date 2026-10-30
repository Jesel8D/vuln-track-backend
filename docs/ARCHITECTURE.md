# Arquitectura implementada

La misión del usuario autoriza este stack para Backend V1. Esto no modifica las
clasificaciones históricas PROPUESTA/PENDIENTE de Context ni D-001/D-002.

`create_app` carga Settings, crea un engine por proceso sin abrir conexiones al importar,
una session factory y el servicio. Lifespan libera el pool. Uvicorn usa factory;
no hay singleton de sesión ni sesiones compartidas entre threads. Endpoints de acceso
a datos son síncronos. Autenticación abre/cierra una sesión y devuelve un objeto sin
hash cargado para las rutas protegidas; el servicio abre su propia transacción.

El middleware ASGI limita el cuerpo, genera correlación independiente del cliente y
añade no-store/nosniff. Los errores de validación no serializan entradas rechazadas.
Excepciones inesperadas se registran con tipo y ubicaciones, sin mensajes/variables;
las excepciones SQL se reducen a clase y SQLSTATE. Deshabilitar logs HTTP de acceso
evita conservar URLs introducidas por usuarios.

El servicio reúne consultas y transacciones pequeñas; una capa de repositorio separada
no aportaría una responsabilidad distinta todavía. Los modelos incluyen las cinco
tablas aunque solo tres participen de V1. FKs representan relaciones reales; no hay
relación de propiedad de Asset. No se expone CRUD de análisis ni hallazgos.

Listado preparado: CTE de registros visibles, página y total en una consulta/snapshot,
orden `(created_at,id)`, sin N+1. Offset máximo 1 000 000 y limit 1–100. No hay filtros
de negocio no aprobados. La autorización productiva conserva el conjunto visible vacío.
El 403 de listado no revela conteos de otros usuarios.

Valores provisionales: NFC + strip, rechazo de controles, JWT 15 minutos, cuerpo 8 KiB,
pool 5+5, ventana idempotente de 24 h sin reutilización ni eliminación automática. Todos
son revisables sin cambiar las decisiones aprobadas de Context.
