from datetime import datetime, timedelta, timezone

import pytest

from tlstool import create_app
from tlstool.database import db
from tlstool.models import Domain, Tls

TEST_DATE_CLIENT = (datetime.now(timezone(timedelta(hours=0, minutes=0))) + timedelta(days=10)).strftime('%Y-%m-%d 00:00:00')
TEST_DATE_TZ = (datetime.now(timezone(timedelta(hours=0, minutes=0))) + timedelta(days=10)).strftime('%Y-%m-%d 00:00:00+00:00')

@pytest.fixture
def client():
    test_app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'postgresql://test_user:test_password@localhost:55432/test_db',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False
    })
    with test_app.app_context():
        db.create_all()

        domain1 = Domain(name='mytestdomain.com', tld='.com', zone_id='ZC123GH456678', tls_exp_date=TEST_DATE_CLIENT, tls_issuer='GlobalSign')
        domain2 = Domain(name='anothertestdomain.com', tld='.com', zone_id='ZC123GH456678', tls_exp_date=TEST_DATE_CLIENT, tls_issuer='Lets Encrypt')
        db.session.add(domain1)
        db.session.add(domain2)

        tls_before = (datetime.now() + timedelta(days=2)).strftime('%Y-%m-%d 00:00:00')
        tls_after = (datetime.now() + timedelta(days=92)).strftime('%Y-%m-%d 00:00:00')
        tls_created = (datetime.now()).strftime('%Y-%m-%d 00:00:00')
        tls1 = Tls(fastly_id='k0ff8jxYcZAq7eWFHI1Xh0', not_after=tls_after, not_before=tls_before, created_at=tls_created)
        tls2 = Tls(fastly_id='05igt3aTwZLG63mUb19J62', not_after=tls_after, not_before=tls_before, created_at=tls_created)
        db.session.add(tls1)
        db.session.add(tls2)

        db.session.commit()

    with test_app.test_client() as client:
        yield client

    with test_app.app_context():
        db.drop_all()

def test_get_domains(client):
    with client.application.app_context():
        test_domains = Domain.query.all()

        assert len(test_domains) == 2
        assert test_domains[0].name == 'mytestdomain.com'
        assert str(test_domains[0].tls_exp_date) == str(TEST_DATE_TZ)
        assert test_domains[0].tls_issuer == 'GlobalSign'

        assert test_domains[1].name == 'anothertestdomain.com'
        assert str(test_domains[1].tls_exp_date) == str(TEST_DATE_TZ)
        assert test_domains[1].tls_issuer == 'Lets Encrypt'

def test_get_tls_records(client):
    with client.application.app_context():
        tls_before = (datetime.now() + timedelta(days=2)).strftime('%Y-%m-%d 00:00:00')
        tls_after = (datetime.now() + timedelta(days=92)).strftime('%Y-%m-%d 00:00:00')
        tls_created = (datetime.now()).strftime('%Y-%m-%d 00:00:00')
        test_tls = Tls.query.all()

        assert len(test_tls) == 2
        assert str(test_tls[0].not_after) == tls_after
        assert str(test_tls[0].not_before) == tls_before
        assert str(test_tls[0].created_at) == tls_created

        assert str(test_tls[1].not_after) == tls_after
        assert str(test_tls[1].not_before) == tls_before
        assert str(test_tls[1].created_at) == tls_created


