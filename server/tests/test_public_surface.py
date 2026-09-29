"""Public API exposure and browser integration regressions."""
from fastapi.testclient import TestClient

from envelock.config import get_settings
from envelock.main import create_app


def test_production_does_not_publish_internal_api_schema(monkeypatch) -> None:
    import envelock.main as main
    settings = get_settings().model_copy(update={"env": "production"})
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    app = create_app()
    paths = {getattr(route, "path", None) for route in app.routes}
    assert "/openapi.json" not in paths
    assert "/docs" not in paths


def test_allowed_browser_can_update_billing_seats() -> None:
    origin = get_settings().cors_origin_list[0]
    client = TestClient(create_app())
    response = client.options("/api/v1/billing/seats", headers={
        "Origin": origin,
        "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "authorization,content-type",
    })
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    assert "PUT" in response.headers["access-control-allow-methods"]
