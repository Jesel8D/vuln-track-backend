# Recuperar V1 + V1.1 y publicar desde Ubuntu/Kubuntu

La entrega no está publicada en GitHub. No se intentó push ni modificar autenticación
en esta misión. Descargar el bundle y conservarlo fuera del entorno Cloud.

Artefactos V1.1 (nombres nuevos; V1 no se sobrescribe):

- `/workspace/shared/downloads/vulntrack-backend-v1.1.bundle`
- `/workspace/shared/downloads/vulntrack-backend-v1.1.patch`

Bundle contiene referencias main (base original) y feat/backend-v1-assets, historial
completo y objetos para base, V1 y todos los commits V1.1. El parche es una serie completa
desde main original hasta HEAD final, no solo un delta sobre V1. La misión verifica
recuperación aislada, integridad Git y equivalencia de árbol del parche; resultados y
commit final se incluyen en el informe de entrega. Estos nombres no implican publicación.

## Recuperación preferida — conserva IDs originales

Suponiendo descarga en `~/Downloads` (en KDE puede ser `~/Descargas`; ajustar la ruta):

```bash
git bundle verify ~/Downloads/vulntrack-backend-v1.1.bundle
git bundle list-heads ~/Downloads/vulntrack-backend-v1.1.bundle
git clone --branch feat/backend-v1-assets \
  ~/Downloads/vulntrack-backend-v1.1.bundle ~/vuln-track-backend-v11
cd ~/vuln-track-backend-v11
git status --short --branch
git log --oneline --decorate --graph --all
git merge-base --is-ancestor 578f74a7b920f3fd07d745ee91713f9d7e5471ec HEAD
git fsck --full
```

Contrastar `git rev-parse HEAD` con el commit final del informe. El clone no necesita
GitHub ni un commit V1 previamente publicado. Mantener también el bundle V1 anterior.

## Publicación SSH — solo desde equipo autorizado

Usar una identidad SSH **ya autorizada** en GitHub. No copiar claves/tokens a Cloud.
Estos comandos son instrucciones para Ubuntu, no se ejecutaron en esta misión:

```bash
cd ~/vuln-track-backend-v11
git remote set-url origin git@github.com:Jesel8D/vuln-track-backend.git
git remote -v
git ls-remote origin refs/heads/main refs/heads/feat/backend-v1-assets
git push -u origin refs/heads/feat/backend-v1-assets:refs/heads/feat/backend-v1-assets
git ls-remote origin refs/heads/feat/backend-v1-assets
git rev-parse HEAD
```

Las dos últimas salidas deben identificar el mismo commit. Si hay rechazo por historial
remoto distinto, detenerse y revisar: nunca usar force, rebase de lo entregado ni cambiar
main para resolverlo. No hay merge automático. Después de publicar, se puede abrir un
PR explícitamente como propuesta pendiente, sin fusionarlo ni aplicar DDL persistente.

## Alternativa de parche completo

El bundle es preferible porque conserva todos los IDs. Si solo queda el parche, partir
del commit base original en un checkout nuevo, sin descartar trabajo existente:

```bash
git clone git@github.com:Jesel8D/vuln-track-backend.git ~/vuln-track-backend-patch
cd ~/vuln-track-backend-patch
git switch -c recovery/backend-v11 b5e71f24ee10793a87b161a3aba3f1b3b19c6d07
git am ~/Downloads/vulntrack-backend-v1.1.patch
git status --short --branch
git fsck --full
```

`git am` puede producir IDs diferentes por datos del committer; el árbol final debe
coincidir con el bundle/informe. El parche incluye V1 y V1.1, sin aplicación manual
previa de V1. No aplicarlo sobre una rama que ya contenga esos commits. Revisar la
publicación de la rama de recuperación por separado, sin sobrescribir la rama entregada.
