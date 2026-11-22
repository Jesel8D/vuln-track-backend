# Preflight de almacenamiento RC2.4

Mediciones del 22 de noviembre de 2026 en Windows 11, Ubuntu 24.04 WSL2 y Docker Desktop.

| Componente | Bytes observados | Ubicación o alcance |
|---|---:|---|
| C: libre al inicio | 3 270 529 024 | SSD físico 0, NTFS |
| F: libre al inicio | 21 415 567 360 | Mismo SSD físico 0, NTFS |
| Disco de Ubuntu, longitud del VHDX | 9 845 080 064 | `%LOCALAPPDATA%\wsl\{GUID}\ext4.vhdx` en C: |
| Docker Desktop, VHDX de datos | 11 809 062 912 | `%LOCALAPPDATA%\Docker\wsl\disk\docker_data.vhdx` en C: |
| Docker Desktop, VHDX de sistema | 100 663 296 | `%LOCALAPPDATA%\Docker\wsl\main\ext4.vhdx` en C: |
| Capacidad lógica libre en Ubuntu | 1 017 563 414 528 | `/`, no equivale a espacio físico de C: |
| Capacidad lógica libre del volumen Docker original | 1 014 463 180 800 | Sistema de archivos del VHDX de Docker |
| Volúmenes del motor | 6,121 GB | 33 volúmenes según `docker system df` |
| Directorio completo PGDATA de RC2.3 | 3 808 987 893 | `vulntrack_v2_rc2_catalog23_pgdata` montado de solo lectura |
| WAL de RC2.3 | 1 073 750 016 | Incluido en PGDATA |
| Base RC2.3 según PostgreSQL | 2 711 714 839 | Copia en RAM tras reproducir el WAL |
| Tabla de productos incluido TOAST e índices | 2 694 766 592 | `vulntrack_catalog.products` |
| Índices de productos | 879 427 584 | Incluidos en la medida anterior |
| Respaldo privado selectivo histórico | 323 009 | `.local/rc2-catalog23/backups`, en WSL y C: |
| Feed comprimido original | 85 329 096 | `.local/rc2-catalog23/cpe-feed/<digest>/dictionary.tar.gz.part` |
| Respaldo cifrado nuevo | 216 402 769 | `F:\VulnTrack-Respaldos\RC24\full-rc23` |
| F: libre después de estas dos copias | 21 113 823 232 | NTFS |

La unidad F: quedó confirmada como `/mnt/f`. Su carpeta privada usa ACL de NTFS con acceso del propietario y SYSTEM. El espacio libre en WSL corresponde a un disco virtual que solo puede crecer mientras C: tenga capacidad física. El directorio activo de PostgreSQL nunca se alojó en NTFS.

El respaldo aplica un presupuesto de dos veces el tamaño de la base más 1 GiB libre en el sistema de archivos de destino. Para duplicar la base de forma persistente, RC2.4 exige al menos **6 497 171 502 bytes** libres en C: con ese mismo criterio. C: no superó el umbral. El ensayo alternativo usó un volumen RAM de 6 GiB con `noswap`, límites de contenedor de 8 GiB y **3 229 974 528 bytes** en C: al verificar el resultado. La base restaurada midió 2 477 702 167 bytes.

Windows identificó dos dispositivos USB independientes con aproximadamente 3,18 GB y 31,37 GB libres. F: y C: comparten SSD. Los USB se inspeccionaron para evaluar una segunda copia y no se escribieron.

[Guía de restauración](V2_RC24_RESTORE_GUIDE.md)
