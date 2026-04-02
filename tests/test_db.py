from app import app, init_db


def test_init_db_creates_file(tmp_path, monkeypatch):
    db_file = tmp_path / "test_inventory.db"
    monkeypatch.setattr("app.DB_PATH", db_file)
    init_db()
    assert db_file.exists()


def test_register_and_login_pages_load():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        assert client.get("/login").status_code == 200
        assert client.get("/setup-admin").status_code == 200
