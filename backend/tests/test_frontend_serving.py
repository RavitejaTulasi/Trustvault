from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.main import SPAStaticFiles


def test_spa_static_files_serve_index_for_client_routes(tmp_path):
    (tmp_path / "index.html").write_text("<main>TrustVault</main>", encoding="utf-8")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log('app')", encoding="utf-8")

    app = FastAPI()
    app.mount("/", SPAStaticFiles(directory=str(tmp_path), html=True), name="frontend")

    with TestClient(app) as client:
        route_response = client.get("/documents/doc-123")
        asset_response = client.get("/assets/app.js")
        missing_asset_response = client.get("/assets/missing.js")
        missing_api_response = client.get("/api/v1/not-a-route")

    assert route_response.status_code == 200
    assert route_response.text == "<main>TrustVault</main>"
    assert asset_response.status_code == 200
    assert asset_response.text == "console.log('app')"
    assert missing_asset_response.status_code == 404
    assert missing_api_response.status_code == 404
