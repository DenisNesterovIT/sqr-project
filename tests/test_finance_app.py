import os
import pytest
import shutil
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from main import Base, app, get_db



# point to an in-memory SQLite for testing
test_db_url = "sqlite:///./test_finance.db"

# Ensure a fresh database for each test session
if os.path.exists("test_finance.db"):
    os.remove("test_finance.db")

# Monkey-patch the application's database URL and recreate tables before import
from main import Base, app, get_db

# Override get_db dependency to use test database
engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(scope="module")
def token():
    # Register a test user
    response = client.post("/register", json={"username": "testuser", "email": "test@example.com", "password": "secret"})
    assert response.status_code == 200
    # Login and return token
    response = client.post("/login", json={"username": "testuser", "password": "secret"})
    assert response.status_code == 200
    return response.json()["access_token"]

def test_create_record_and_dashboard(token):
    headers = {"Authorization": f"Bearer {token}"}
    # Create income record
    resp = client.post("/records", json={"amount": 100.0, "type": "income", "category": "Salary"}, headers=headers)
    assert resp.status_code == 200
    record_id = resp.json()["record_id"]
    assert isinstance(record_id, int)
    # Create expense record
    resp = client.post("/records", json={"amount": 40.0, "type": "expense", "category": "Food"}, headers=headers)
    assert resp.status_code == 200
    # Fetch dashboard
    resp = client.get("/dashboard", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_income"] == 100.0
    assert data["total_expense"] == 40.0
    assert data["balance"] == pytest.approx(60.0)
    assert any(rec["id"] == record_id for rec in data["records"])

def test_update_and_delete_record(token):
    headers = {"Authorization": f"Bearer {token}"}
    # Create a record to update/delete
    resp = client.post("/records", json={"amount": 20.0, "type": "expense", "category": "Snacks"}, headers=headers)
    rec_id = resp.json()["record_id"]
    # Update it
    resp = client.put(f"/records/{rec_id}", json={"amount": 25.0}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["record_id"] == rec_id
    # Verify updated amount in dashboard
    resp = client.get("/dashboard", headers=headers)
    data = resp.json()["records"]
    updated = next(r for r in data if r["id"] == rec_id)
    assert updated["amount"] == 25.0
    # Delete it
    resp = client.delete(f"/records/{rec_id}", headers=headers)
    assert resp.status_code == 200
    # Verify deletion
    resp = client.get("/dashboard", headers=headers)
    assert not any(r["id"] == rec_id for r in resp.json()["records"])  

def test_category_endpoints(token):
    headers = {"Authorization": f"Bearer {token}"}
    # Create a category
    resp = client.post("/categories", json={"name": "Travel"}, headers=headers)
    assert resp.status_code == 200
    cat = resp.json()
    assert cat["name"] == "Travel"
    # Get categories
    resp = client.get("/categories", headers=headers)
    assert resp.status_code == 200
    cats = resp.json()
    assert any(c["name"] == "Travel" for c in cats)

# Cleanup test database file
def teardown_module(module):
    try:
        os.remove("test_finance.db")
    except FileNotFoundError:
        pass
