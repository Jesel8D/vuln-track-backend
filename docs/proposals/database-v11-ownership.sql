-- PROPUESTA para revisión/coordinación con Database. No aplicada a bases persistentes.
-- Equivalente de 0002_asset_owner; NO ejecutar además de Alembic en la misma instalación.
-- El responsable debe envolverla en una transacción y verificar V1 antes/V1.1 después.
-- No hay backfill: los activos históricos permanecen con propietario NULL.
ALTER TABLE vulntrack.assets
    ADD COLUMN created_by uuid NULL,
    ADD CONSTRAINT assets_created_by_fkey FOREIGN KEY (created_by)
        REFERENCES vulntrack.users(id) ON DELETE RESTRICT;
CREATE INDEX assets_owner_created_id_idx
    ON vulntrack.assets (created_by, created_at, id);
