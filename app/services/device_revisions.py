"""Shared record revision rules. PostgreSQL writes the authoritative ledger."""

from sqlalchemy import text

from app.core.errors import APIError
from app.schemas.cpe import parse_cpe, unbind_component

TECHNOLOGICAL = ("component_kind", "product_vendor", "product", "version")
PHYSICAL = ("device_type", "manufacturer", "model")
EDITABLE = (*PHYSICAL, "site_label", "inventory_label", "notes", "status", *TECHNOLOGICAL)


def edit_reason(session, reason):
    session.execute(
        text("SELECT set_config('vulntrack.device_edit_reason', :reason, true)"), {"reason": reason}
    )


def require_version(row, expected):
    if row["record_version"] != expected:
        raise APIError(409, "DEVICE_VERSION_CONFLICT", "El dispositivo cambió. Recarga y compara.")


def edit_device(session, row, scope, payload):
    require_version(row, payload.expected_record_version)
    values = payload.model_dump(exclude_unset=True)
    changes = {
        name: values[name] for name in EDITABLE if name in values and row[name] != values[name]
    }
    if changes.keys() & {*PHYSICAL, *TECHNOLOGICAL} and not payload.confirm_sensitive:
        raise APIError(
            409, "DEVICE_CHANGE_CONFIRMATION_REQUIRED", "Confirma el cambio de identidad"
        )
    if not changes:
        return
    edit_reason(session, payload.reason)
    # Identifiers are drawn exclusively from the explicit editable column tuple.
    assignments = ", ".join(f"{name}=:{name}" for name in changes)
    changed = session.execute(
        text(
            f"UPDATE vulntrack_devices.devices SET {assignments} "
            "WHERE workspace_id=:workspace AND id=:device AND record_version=:expected"
        ),
        {**scope, **changes, "expected": payload.expected_record_version},
    )
    if changed.rowcount != 1:
        raise APIError(409, "DEVICE_VERSION_CONFLICT", "El dispositivo cambió. Recarga y compara.")


def present_run(value):
    if value["evaluated_technology"] is None:
        try:
            _, vendor, product, *_ = parse_cpe(value["selected_cpe"])
            vendor, product = unbind_component(vendor), unbind_component(product)
        except ValueError:
            vendor, product = None, None
        value["evaluated_technology"] = {
            "product_vendor": vendor,
            "product": product,
            "observed_version": value["observed_version"],
            "component_kind": None,
            "record_version": None,
            "identity_generation": value["identity_generation"],
            "basis": "historical_cpe",
        }
    return value
