import pytest

from tlstool import create_app


@pytest.fixture
def client():
    test_app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'postgresql://test_user:test_password@localhost:55432/test_db',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False
    })
    with test_app.test_client() as client:
        yield client

def test_healthcheck(client):
    with client.application.app_context():
        healthcheck = client.get('/healthcheck')

        assert healthcheck.status_code == 200
        assert healthcheck.data == b'<p>Hello World</p>'
