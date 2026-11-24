"""Transactional RC3 edits with signed identity, fixture CVE and real concurrency."""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from app.db.workspace_context import workspace_session
from app.services.cpe_catalog import UPSERT, normalize, refresh_summary
from scripts.disposable_v2 import DisposableV2
from tests.integration.test_rc2_devices import ROUTER, api, confirm, create, owner  # noqa: F401

pytestmark = pytest.mark.postgres


def response(client, user, path):
    result = client.get(path, headers=user["headers"])
    assert result.status_code == 200, result.json()
    return result.json()


def edit(client, user, path, number, **fields):
    return client.patch(
        path,
        headers=user["headers"],
        json={
            "expected_record_version": number,
            "reason": "Observación de un equipo de prueba",
            **fields,
        },
    )


def selections(postgres):
    capture = Path(__file__).resolve().parents[1] / "fixtures/nvd_cpe_verified.json"
    base = json.loads(capture.read_text())["products"][0]
    results = []
    with postgres.begin() as db:
        for version in ("1.0.0.33", "1.0.1.16"):
            entry = json.loads(json.dumps(base))
            entry["cpe"]["cpeNameId"] = str(uuid4())
            entry["cpe"]["cpeName"] = entry["cpe"]["cpeName"].replace(":1.0.0.33:", f":{version}:")
            item = normalize(entry, "fixture", None)
            db.execute(UPSERT, item)
            results.append(
                {
                    "cpe_name_id": str(item["cpe_name_id"]),
                    "expected_cpe_name": item["cpe_name"],
                    "expected_nvd_modified": item["nvd_modified"].isoformat(),
                    "mode": "fixture",
                    "reason": "Comparado con la versión observada",
                    "confirmed": True,
                    "expected_identification_id": None,
                }
            )
        refresh_summary(db, "fixture")
    return results


def test_edit_reidentify_and_preserve_cve_evidence(api, postgres):  # noqa: F811
    app, client = api
    endpoint, actor = owner(app, client)
    device = create(client, endpoint, actor)
    headers = actor["headers"]
    selected = confirm(client, device, actor)
    assert selected.status_code == 201, selected.json()
    identification = selected.json()
    key = headers | {"Idempotency-Key": str(uuid4())}
    result = client.post(device + "/analyses", headers=key)
    assert result.status_code == 201, result.json()
    history = result.json()
    finding_path = device + "/analyses/" + history["id"] + "/findings"
    finding = response(client, actor, finding_path)["items"][0]
    review_path = device + "/findings/" + finding["id"]
    assert (
        client.patch(
            review_path,
            headers=headers,
            json={
                "applicability": "undetermined",
                "expected_updated_at": finding["updated_at"],
                "reason": "Revisión humana de fixture",
                "evidence": "Faltan condiciones de plataforma",
            },
        ).status_code
        == 200
    )
    recommendation_path = review_path + "/recommendations"
    assert (
        client.post(
            recommendation_path,
            headers=key,
            json={
                "recommendation": "Consultar documentación oficial",
            },
        ).status_code
        == 201
    )
    reviewed = response(client, actor, finding_path)
    recommendations = response(client, actor, recommendation_path)
    change = edit(client, actor, device, 1, site_label="Sala B", notes="Nota privada de ensayo")
    assert change.status_code == 200, change.json()
    assert change.json()["current_identification"]["id"] == identification["id"]
    assert change.json()["record_version"] == 2
    assert edit(client, actor, device, 2, model="RV340 corregido").status_code == 409
    physical = edit(client, actor, device, 2, model="RV340 corregido", confirm_sensitive=True)
    assert physical.status_code == 200 and physical.json()["cpe_review_state"] == "confirmed"

    changed = edit(client, actor, device, 3, version="1.0.1.16", confirm_sensitive=True)
    assert changed.status_code == 200, changed.json()
    assert changed.json()["cpe_review_state"] == "needs_review"
    assert changed.json()["current_identification"] is None
    assert response(client, actor, device + "/identifications")["items"] == [identification]
    fresh = headers | {"Idempotency-Key": str(uuid4())}
    blocked = client.post(device + "/analyses", headers=fresh)
    assert (
        blocked.status_code == 409
        and blocked.json()["error"]["code"] == "CPE_CONFIRMATION_REQUIRED"
    )
    historical = client.post(device + "/analyses", headers=key).json()
    assert historical["assessment"]["correspondence"] == "historical"
    assert historical["assessment"]["requires_new_query"]
    assert not historical["is_current_technology"]
    assert (
        historical | {"assessment": history["assessment"], "is_current_technology": True} == history
    )
    assert historical["evaluated_technology"]["observed_version"] == "1.0.0.33"
    findings_after = response(client, actor, finding_path)
    assert findings_after["analysis"] == historical
    assert findings_after | {"analysis": reviewed["analysis"]} == reviewed
    assert response(client, actor, recommendation_path) == recommendations

    revisions = response(client, actor, device + "/revisions")["items"]
    assert [r["change_kind"] for r in revisions] == ["technological", "physical", "administrative"]
    assert revisions[0]["actor_id"] == actor["id"]
    assert (
        revisions[0]["recorded_at"]
        and revisions[0]["related_identification_id"] == identification["id"]
    )
    assert revisions[0]["previous_values"]["version"] == "1.0.0.33"
    assert revisions[0]["new_values"]["version"] == "1.0.1.16"
    assert "Nota privada de ensayo" not in json.dumps(revisions)
    interval = response(client, actor, device + "/revisions/compare?from_version=1&to_version=4")
    assert set(interval["changed_fields"]) == {"notes", "site_label", "model", "version"}

    previous, candidate = selections(postgres)
    wrong = client.post(
        device + "/reidentification",
        headers=headers,
        json=previous | {"expected_record_version": 4},
    )
    assert wrong.status_code == 409 and wrong.json()["error"]["code"] == "CPE_VERSION_MISMATCH"
    found = response(client, actor, "/api/v2/cpe-catalog/candidates?mode=fixture&version=1.0.1.16")
    assert candidate["cpe_name_id"] in [item["cpe_name_id"] for item in found["items"]]
    reconfirmed = client.post(
        device + "/reidentification",
        headers=headers,
        json=candidate | {"expected_record_version": 4},
    )
    assert reconfirmed.status_code == 201, reconfirmed.json()
    assert (
        response(client, actor, device)["current_identification"]["id"] == reconfirmed.json()["id"]
    )
    assert response(client, actor, device + "/identifications")["page"]["total"] == 2

    unknown = edit(
        client, actor, device, 4, version=None, product_vendor="Otro", confirm_sensitive=True
    )
    assert unknown.status_code == 200 and unknown.json()["cpe_review_state"] == "needs_review"
    assert (
        client.post(
            device + "/reidentification",
            headers=headers,
            json=candidate
            | {
                "expected_record_version": 5,
            },
        ).json()["error"]["code"]
        == "VERSION_REQUIRED"
    )
    assert edit(client, actor, device, 5, notes="token=prueba").status_code == 422
    assert edit(client, actor, device, 5, actor_id=actor["id"]).status_code == 422


def test_concurrent_editors_and_immutable_workspace_history(api, postgres):  # noqa: F811
    app, client = api
    endpoint, first = owner(app, client)
    _, second = owner(app, client)
    _, viewer = owner(app, client)
    _, outsider = owner(app, client)
    device = create(client, endpoint, first)
    with postgres.begin() as db:
        db.execute(
            text(
                "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                "VALUES (:w,:e,'editor'),(:w,:v,'viewer')"
            ),
            {"w": first["workspace"], "e": second["id"], "v": viewer["id"]},
        )
    assert edit(client, viewer, device, 1, site_label="No autorizado").status_code == 404
    assert edit(client, outsider, device, 1, site_label="No autorizado").status_code == 404
    assert client.get(device + "/revisions", headers=outsider["headers"]).status_code == 404

    barrier = Barrier(2)

    def update(args):
        user, label = args
        barrier.wait(timeout=10)
        return user, label, edit(client, user, device, 1, site_label=label)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(update, [(first, "Sala A"), (second, "Sala B")]))
    assert sorted(item[2].status_code for item in results) == [200, 409]
    winner, label, _ = next(item for item in results if item[2].status_code == 200)
    rejected = next(item[2] for item in results if item[2].status_code == 409)
    assert rejected.json()["error"]["code"] == "DEVICE_VERSION_CONFLICT"
    listing = response(client, viewer, device + "/revisions")
    assert listing["page"]["total"] == 1
    assert listing["items"][0]["actor_id"] == winner["id"]
    assert response(client, viewer, device)["site_label"] == label
    assert (
        client.get(
            device + "/revisions/compare?from_version=1&to_version=2", headers=outsider["headers"]
        ).status_code
        == 404
    )

    with (
        pytest.raises(DBAPIError),
        workspace_session(
            app.state.session_factory,
            app.state.settings,
            first["id"],
            first["workspace"],
        ) as db,
    ):
        db.execute(text("UPDATE vulntrack_devices.revisions SET reason='Cambiado'"))
    with (
        pytest.raises(DBAPIError),
        workspace_session(
            app.state.session_factory,
            app.state.settings,
            first["id"],
            first["workspace"],
        ) as db,
    ):
        db.execute(text("UPDATE vulntrack_devices.devices SET site_label='Sin revision'"))
    assert response(client, viewer, device + "/revisions") == listing


def test_upgrade_from_rc24_keeps_the_existing_device_identity(postgres):
    assert postgres is not None
    with DisposableV2(
        "existing", sql_checks=False, verification_revision="v2_0006_cpe_quarantine"
    ) as old:
        engine = create_engine(old.url("postgres"), hide_parameters=True)
        workspace, device, identity, run = (uuid4() for _ in range(4))
        values = {"w": workspace, "d": device, "i": identity, "r": run, "k": uuid4(), **ROUTER}
        with engine.begin() as db:
            values["a"] = db.scalar(text("SELECT id FROM vulntrack.users ORDER BY id LIMIT 1"))
            db.execute(
                text(
                    "INSERT INTO vulntrack.workspaces(id,name,created_by) "
                    "VALUES (:w,'Migration test',:a)"
                ),
                values,
            )
            db.execute(
                text(
                    "INSERT INTO vulntrack.workspace_members(workspace_id,user_id,role) "
                    "VALUES (:w,:a,'owner') ON CONFLICT DO NOTHING"
                ),
                values,
            )
            db.execute(
                text("""
                INSERT INTO vulntrack_devices.devices
                (id,workspace_id,created_by,device_type,manufacturer,model,product_vendor,product,
                 component_kind,version,site_label)
                VALUES (:d,:w,:a,:device_type,:manufacturer,:model,:product_vendor,:product,
                        :component_kind,:version,:site_label)
            """),
                values,
            )
            values["cpe"] = "cpe:2.3:o:cisco:small_business_rv340_firmware:1.0.0.33:*:*:*:*:*:*:*"
            db.execute(
                text("""INSERT INTO vulntrack_devices.identifications
                (id,workspace_id,device_id,recorded_by,cpe_name,cpe_name_id,mode,reason)
                VALUES (:i,:w,:d,:a,:cpe,:k,'fixture','Migración de muestra')"""),
                values,
            )
            db.execute(
                text("""INSERT INTO vulntrack_devices.runs
                (id,workspace_id,device_id,identification_id,initiated_by,request_key,
                 selected_cpe,observed_version,mode)
                VALUES (:r,:w,:d,:i,:a,:k,:cpe,:version,'fixture')"""),
                values,
            )
        old.verification_migrate()
        with engine.connect() as db:
            assert db.execute(
                text("SELECT id,record_version,identity_generation FROM vulntrack_devices.devices")
            ).one() == (device, 1, 1)
            assert db.execute(
                text(
                    "SELECT id,cpe_name,identity_generation FROM vulntrack_devices.identifications"
                )
            ).one() == (identity, values["cpe"], 1)
            assert db.execute(
                text("SELECT id,identification_id,observed_version FROM vulntrack_devices.runs")
            ).one() == (run, identity, "1.0.0.33")
            assert db.scalar(text("SELECT count(*) FROM vulntrack_devices.revisions")) == 0
        engine.dispose()
