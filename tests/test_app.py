import pytest
from fastapi.testclient import TestClient
from main import app, Base, engine, SessionLocal


Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

client = TestClient(app)

TEST_USER = {
    "username": "testuser",
    "email": "test@example.com",
    "password": "testpass123"
}

@pytest.fixture(scope="module")
def auth_token():
    r = client.post("/register", json=TEST_USER)
    assert r.status_code in (200, 400)

    r = client.post("/login", json={
        "username": TEST_USER["username"],
        "password": TEST_USER["password"]
    })
    assert r.status_code == 200
    token = r.json()["access_token"]
    return token


def test_register_and_login(auth_token):
    assert auth_token


def test_create_record(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    record = {
        "amount": 100.0,
        "type": "income",
        "category": "Salary",
        "description": "Test salary"
    }
    r = client.post("/records", json=record, headers=headers)
    assert r.status_code == 200
    assert "record_id" in r.json()


def test_get_dashboard(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    r = client.get("/dashboard", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert "total_income" in data
    assert "balance" in data
    assert data["total_income"] >= 0


def test_create_category(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    r = client.post("/categories", json={"name": "Test Category"}, headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "Test Category"


def test_get_categories(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    r = client.get("/categories", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert any(cat["name"] == "Test Category" for cat in data)


def test_get_profile(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    r = client.get("/profile", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["username"] == TEST_USER["username"]



def test_failed_login_and_lockout():
    bad_user = {"username": "updateduser", "password": "wrongpass"}
    for i in range(5):
        r = client.post("/login", json=bad_user)
        assert r.status_code == 401 or r.status_code == 403
    r = client.post("/login", json=bad_user)
    assert r.status_code == 403
    assert "locked" in r.json()["detail"]

def test_update_and_delete_record(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    record = {
        "amount": 50.0,
        "type": "expense",
        "category": "Food"
    }
    r = client.post("/records", json=record, headers=headers)
    assert r.status_code == 200
    record_id = r.json()["record_id"]

    r = client.put(f"/records/{record_id}", json={"amount": 75.0}, headers=headers)
    assert r.status_code == 200
    assert r.json()["record_id"] == record_id

    r = client.delete(f"/records/{record_id}", headers=headers)
    assert r.status_code == 200
    assert "deleted" in r.json()["message"]


def test_get_report(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    r = client.get("/report", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict)

    r = client.get("/report?period=yearly", headers=headers)
    assert r.status_code == 200
    assert isinstance(r.json(), dict)


def test_error_metrics_endpoint():
    r = client.get("/metrics/errors")
    assert r.status_code == 200
    data = r.json()
    assert "error_rate_percent" in data
    assert "error_count" in data
