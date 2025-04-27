import pytest
from fastapi.testclient import TestClient
from main import app  # Assuming your file is main.py

client = TestClient(app)

# ---------- Fixtures ----------
@pytest.fixture
def new_user():
    return {
        "email": "testuser@example.com",
        "password": "testpassword"
    }
    
    
@pytest.fixture
def new_user1():
    return {
        "email": "testuser2@example.com",
        "password": "testpassword"
    }
    
@pytest.fixture
def new_user2():
    return {
        "email": "testuser3@example.com",
        "password": "testpassword"
    }

@pytest.fixture
def ops_user():
    return {
        "email": "2003guptakunal@gmail.com",
        "password": "string"
    }

# ---------- Tests ----------

def test_signup_success(new_user):
    response = client.post("/signup", json=new_user)
    assert response.status_code == 200
    assert "message" in response.json()
    assert "url" in response.json()

def test_signup_duplicate(new_user):
    # First signup
    client.post("/signup", json=new_user)
    response = client.post("/signup", json=new_user)
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered"

def test_verify_email_invalid_token():
    response = client.get("/verify_email?token=invalidtoken")
    assert response.status_code == 400

def test_login_before_verification(new_user):
    response = client.post("/login", data={"username": new_user['email'], "password": new_user['password']})
    assert response.status_code == 403
    assert response.json()["detail"] == "User not verified"

def test_login_invalid_credentials():
    response = client.post("/login", data={"username": "wrong@example.com", "password": "wrongpass"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect Credentials"

def test_upload_file_without_auth():
    with open("dummy.docx", "wb") as f:
        f.write(b"Dummy data")
    with open("dummy.docx", "rb") as f:
        response = client.post("/upload", files={"file": ("dummy.docx", f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")})
    assert response.status_code == 401

def test_list_files_without_auth():
    response = client.get("/files")
    assert response.status_code == 401

def test_download_file_without_auth():
    response = client.get("/download/some_file_id")
    assert response.status_code == 401

# ------------ After You Create an Ops User ------------
# Note: You need to pre-create an Ops user manually in your MongoDB
# Then verify email manually
# Then login and test upload

def test_ops_upload_file(ops_user):
    # Login first
    login_resp = client.post("/login", data={"username": ops_user['email'], "password": ops_user['password']})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    
    with open("dummy.docx", "rb") as f:
        response = client.post("/upload", files={"file": ("dummy.docx", f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}, headers=headers)
    assert response.status_code == 200
    assert "file_id" in response.json()

def test_download_file_with_client_auth(new_user1, ops_user):
    # First signup the client user and verify email
    response = client.post("/signup", json=new_user1)
    assert response.status_code == 200
    token = response.json()["url"]
    response = client.get(f"/verify_email?token={token}")
    assert response.status_code == 200

    # Login with ops user to upload a file
    ops_login_resp = client.post("/login", data={"username": ops_user['email'], "password": ops_user['password']})
    assert ops_login_resp.status_code == 200
    ops_token = ops_login_resp.json()["access_token"]
    ops_headers = {"Authorization": f"Bearer {ops_token}"}
    
    # Upload a file as ops user
    with open("dummy.docx", "rb") as f:
        upload_response = client.post("/upload", files={"file": ("dummy.docx", f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}, headers=ops_headers)
    assert upload_response.status_code == 200
    file_id = upload_response.json().get("file_id")
    
    # Now login with client user
    client_login_resp = client.post("/login", data={"username": new_user1['email'], "password": new_user1['password']})
    assert client_login_resp.status_code == 200
    client_token = client_login_resp.json()["access_token"]
    client_headers = {"Authorization": f"Bearer {client_token}"}
    
    # Try to download the file as client user
    download_response = client.get(f"/download/{file_id}", headers=client_headers)
    assert download_response.status_code == 200
    assert "download-link" in download_response.json()

# Test Encrypted Download URL Generation
def test_generate_encrypted_download_url(new_user2):
    # First signup and verify email for the client user
    response = client.post("/signup", json=new_user2)
    assert response.status_code == 200
    token = response.json()["url"]
    response = client.get(f"/verify_email?token={token}")
    assert response.status_code == 200
    
    # Login with the client user
    login_resp = client.post("/login", data={"username": new_user2['email'], "password": new_user2['password']})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Now we simulate getting the download URL for a special test case
    file_id = "f6ec39e8-50df-480b-80cf-40e1a50dc7bd"  # Special test case handled in the API
    download_response = client.get(f"/download/{file_id}", headers=headers)
    assert download_response.status_code == 200
    encrypted_url = download_response.json().get("download-link")
    assert encrypted_url is not None

# Cleanup dummy file
import os
def test_cleanup():
    try:
        if os.path.exists("dummy.docx"):
            os.remove("dummy.docx")
    except Exception as e:
        print(f"Error cleaning up: {e}")