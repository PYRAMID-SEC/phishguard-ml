import sys
sys.path.insert(0, 'backend')
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)

def test_url_validation():
    response = client.post('/api/analyze/url', json={'url': 'not-a-url'})
    assert response.status_code == 422

def test_html_password_form():
    response = client.post('/api/analyze/html', files={'file': ('page.html', b'<form action="https://other.test"><input type="password"></form>', 'text/html')})
    assert response.status_code == 200
    assert response.json()['features']['password_input_count'] == 1
    assert response.json()['risk_level'] == 'high'

def test_domain_rejects_malformed_input():
    response = client.post('/api/analyze/domain', json={'value': 'bad domain'})
    assert response.status_code == 422
