from datetime import datetime, timedelta
import logging
from unittest.mock import patch, MagicMock

from pyasn1.codec.der import encoder
from pyasn1_modules.rfc2459 import GeneralName
import pytest

from tlstool import create_app
from tlstool.database import db
from tlstool.domains import DomainManager
from tlstool.domains import OpenSSL, ssl
from tlstool.domains import SubjectAltName
from tlstool.models import Domain

domains = DomainManager()

TEST_DATE_INRANGE = (datetime.now() + timedelta(days=10)).strftime('%Y-%m-%d 00:00:00')
TEST_DATE_OUTRANGE = (datetime.now() + timedelta(days=40)).strftime('%Y-%m-%d 00:00:00')
NS = 'ns-5782.awsdns-14.org. ns-459.awsdns-01.com.'

logger = logging.getLogger(__name__)


@pytest.fixture
def client():
    test_app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'postgresql://test_user:test_password@localhost:55432/test_db',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False
    })

    with test_app.app_context():
        db.create_all()
        db.session.commit()

    with test_app.test_client() as client:
        yield client

    with test_app.app_context():
        db.drop_all()

def test_search_domains(client, caplog):
    caplog.set_level(logging.INFO)
    with client.application.app_context():
        # not in exclusion list, tls_issuer != 'Lets Encrypt', status = 'Active', owned = True, expires within 15 days
        domain_one = Domain(
            name='theoffside.com',
            tld='.com',
            zone_id='ZC123ZZ549978',
            nameservers=NS,
            tls_exp_date=TEST_DATE_INRANGE,
            tls_issuer='GlobalSign',
            status='Active',
            owned=True
        )
        db.session.add(domain_one)

        # not in exclusion list, tls_issuer != 'Lets Encrypt', status = 'Active', owned = True, not expiring
        domain_two = Domain(
            name='examplethreeb.com',
            tld='.com',
            zone_id='ZC123ZZ549978',
            nameservers=NS,
            tls_exp_date=TEST_DATE_OUTRANGE,
            tls_issuer='GlobalSign',
            status='Active',
            owned=True
        )
        db.session.add(domain_two)

        # not in exclusion list, tls_issuer == 'Lets Encrypt', status = 'Active', owned = True, expires within 15 days
        domain_three = Domain(
            name='examplesix.com',
            tld='.com',
            zone_id='ZC12D3549978D',
            nameservers=NS,
            tls_exp_date=TEST_DATE_INRANGE,
            tls_issuer='Lets Encrypt',
            status='Active',
            owned=True
        )
        db.session.add(domain_three)

        # in exclusion list
        domain_four = Domain(
            name='exampletwo.com',
            tld='.com',
            zone_id='ZC123GH456678',
            nameservers=NS,
            tls_exp_date=TEST_DATE_INRANGE,
            tls_issuer='GlobalSign',
            status='Active',
            owned=True
        )
        db.session.add(domain_four)

        db.session.commit()
        db.session.flush()

        test_domains = domains.search_domains()

        assert len(test_domains) == 3
        assert isinstance(test_domains, list)

        assert isinstance(test_domains[0], dict)
        assert test_domains[0]['domain'] == 'theoffside.com'
        assert str(test_domains[0]['tls_exp_date']) == str(TEST_DATE_INRANGE)+'+00:00'
        assert test_domains[0]['tls_issuer'] == 'GlobalSign'
        assert test_domains[0]['zone_id'] == 'ZC123ZZ549978'

        assert isinstance(test_domains[1], dict)
        assert test_domains[1]['domain'] == 'examplethreeb.com'
        assert str(test_domains[1]['tls_exp_date']) == str(TEST_DATE_OUTRANGE)+'+00:00'
        assert test_domains[1]['tls_issuer'] == 'GlobalSign'
        assert test_domains[1]['zone_id'] == 'ZC123ZZ549978'

        assert isinstance(test_domains[2], dict)
        assert test_domains[2]['domain'] == 'examplesix.com'
        assert str(test_domains[2]['tls_exp_date']) == str(TEST_DATE_INRANGE)+'+00:00'
        assert test_domains[2]['tls_issuer'] == 'Lets Encrypt'
        assert test_domains[2]['zone_id'] == 'ZC12D3549978D'

        assert 'Search for domains with certs not issued by LE' in caplog.text
        assert 'All active certs issued by LE, within renewal range' in caplog.text

def test_domain_meta(client):
    with client.application.app_context():
        domain = 'examplemeta.com'
        domain_entry = Domain(
            name=domain,
            tld='.com',
            zone_id='ZC12D3549978D',
            tls_exp_date=TEST_DATE_INRANGE,
            tls_issuer='Lets Encrypt',
        )
        db.session.add(domain_entry)
        db.session.commit()

        result = domains.domain_meta(domain)

        assert len(result) == 1
        assert isinstance(result, list)
        assert isinstance(result[0], dict)
        assert result[0]['domain'] == 'examplemeta.com'
        assert str(result[0]['tls_exp_date']) == str(TEST_DATE_INRANGE)+'+00:00'
        assert result[0]['tls_issuer'] == 'Lets Encrypt'
        assert result[0]['zone_id'] == 'ZC12D3549978D'

@patch("tlstool.domains.DomainManager._get_cert_subjects")
@patch("tlstool.domains.ssl.get_server_certificate")
@patch("tlstool.domains.OpenSSL.crypto.load_certificate")
def test_get_domain_tls_status_ok(mock_load_cert, mock_get_cert, mock_cert_subjects, client):
    with client.application.app_context():
        mock_get_cert.return_value = 'cert_string'
        test_date_outofrange = datetime.strptime(TEST_DATE_OUTRANGE, '%Y-%m-%d %H:%M:%S')
        cert_not_expired = (test_date_outofrange.strftime('%Y%m%d%H%M%S') + 'Z').encode('utf-8')
        mock_load_cert.return_value.get_notAfter.return_value = cert_not_expired

        domain = 'example.com'
        tls_issuer = 'Lets Encrypt'
        mock_cert_subjects.return_value = [domain]

        domain_entry = Domain(name=domain, tls_issuer=tls_issuer, tls_exp_date=TEST_DATE_INRANGE, tld='.com')
        db.session.add(domain_entry)
        db.session.commit()

        status = domains.get_domain_tls_status(domain, tls_issuer)
        assert status == 'ok'

@patch("tlstool.domains.DomainManager._get_cert_subjects")
@patch("tlstool.domains.ssl.get_server_certificate")
@patch("tlstool.domains.OpenSSL.crypto.load_certificate")
def test_get_domain_tls_status_renew(mock_load_cert, mock_get_cert, mock_cert_subjects, client):
    with client.application.app_context():
        mock_get_cert.return_value = 'cert_string'
        test_date_inrange = datetime.strptime(TEST_DATE_INRANGE, '%Y-%m-%d %H:%M:%S')
        cert_expiring_soon = (test_date_inrange.strftime('%Y%m%d%H%M%S') + 'Z').encode('utf-8')
        mock_load_cert.return_value.get_notAfter.return_value = cert_expiring_soon
    
        domain = 'example.com'
        tls_issuer = 'Lets Encrypt'
        mock_cert_subjects.return_value = [domain]

        domain_entry = Domain(name=domain, tls_issuer=tls_issuer, tls_exp_date=TEST_DATE_INRANGE, tld='.com')
        db.session.add(domain_entry)
        db.session.commit()

        status = domains.get_domain_tls_status(domain, tls_issuer)
        assert status == 'renew'

@patch("tlstool.domains.ssl.get_server_certificate")
def test_get_domain_tls_status_unavailable(mock_get_cert):
    domain = 'example.com'
    tls_issuer = 'Lets Encrypt'
    mock_get_cert.side_effect=ssl.SSLEOFError

    status = domains.get_domain_tls_status(domain, tls_issuer)
    assert status == 'unavailable'

@patch("tlstool.domains.DomainManager._get_cert_subjects")
@patch("tlstool.domains.ssl.get_server_certificate")
@patch("tlstool.domains.OpenSSL.crypto.load_certificate")
def test_get_domain_tls_status_new_issuer(mock_load_cert, mock_get_cert, mock_cert_subjects, client):
    with client.application.app_context():
        mock_get_cert.return_value = 'cert_string'
        test_date_outofrange = datetime.strptime(TEST_DATE_OUTRANGE, '%Y-%m-%d %H:%M:%S')
        cert_not_expired = (test_date_outofrange.strftime('%Y%m%d%H%M%S') + 'Z').encode('utf-8')
        mock_load_cert.return_value.get_notAfter.return_value = cert_not_expired
    
        domain = 'example.com'
        tls_issuer = 'GlobalSign'
        mock_cert_subjects.return_value = [domain]

        domain_entry = Domain(name=domain, tls_issuer=tls_issuer, tls_exp_date=TEST_DATE_INRANGE, tld='.com')
        db.session.add(domain_entry)
        db.session.commit()

        status = domains.get_domain_tls_status(domain, tls_issuer)
        assert status == 'new'

def test_get_cert_subjects():
    mock_x509 = MagicMock(spec=OpenSSL.crypto.X509)
    mock_x509.get_extension_count.return_value = 1

    mock_extension_1 = MagicMock()
    mock_extension_1.get_short_name.return_value = b'subjectAltName'

    san = SubjectAltName()
    san.setComponentByPosition(0, GeneralName().setComponentByName('dNSName', 'theoffside.com'))
    san.setComponentByPosition(1, GeneralName().setComponentByName('dNSName', '*.theoffside.com'))
    der_encoded_names = encoder.encode(san)
    mock_extension_1.get_data.return_value = der_encoded_names

    mock_x509.get_extension.return_value = mock_extension_1

    mock_subject = MagicMock()
    mock_subject.get_components.return_value = [(b'CN', b'theoffside.com')]
    mock_x509.get_subject.return_value = mock_subject

    # patch replaces the X509 class with the mock
    with patch('OpenSSL.crypto.X509', return_value=mock_x509):
        x509_instance = OpenSSL.crypto.X509()

        subjects = domains._get_cert_subjects(x509_instance)

        assert isinstance(subjects, list)
        assert '*.theoffside.com' in subjects
        assert 'theoffside.com' in subjects

def test_domain_update(client):
    with client.application.app_context():
        domain_obj = Domain(
            name='theoffside.com',
            tld='.com',
            zone_id='ZC123ZZ549978',
            nameservers=NS,
            tls_exp_date=TEST_DATE_INRANGE,
            tls_issuer='GlobalSign',
            status='Active',
            owned=True
        )
        db.session.add(domain_obj)
        db.session.commit()

        cert_obj_one = {'cert': {'data': {
            'id': 'krKPPix0ykWAQKiAdFfZZZ',
            'attributes': {'not_after': '2024-02-04 16:06:57', 'not_before': '2023-11-06 16:06:58', 'created_at': '2025-07-22 17:07:00'},
            'relationships': {'tls_domains': {'data': [{'id': '*.alligatorarmy.com'}]}}
        }}}
        cert_obj_two = {'cert': {'data': {
            'id': 'krKPPix0ykWAQKiAdFfSSS',
            'attributes': {'not_after': '2024-02-04 16:06:57', 'not_before': '2023-11-06 16:06:58', 'created_at': '2025-07-22 17:07:00'},
            'relationships': {'tls_domains': {'data': [{'id': '*.theoffside.com'}]}}
        }}}
        cert_obj_three = {'cert': {'data': {
            'id': 'krKPPix0ykWAQKiAdFfFDT',
            'attributes': {'not_after': '2024-02-04 16:06:57', 'not_before': '2023-11-06 16:06:58', 'created_at': '2025-07-22 17:07:00'},
            'relationships': {'tls_domains': {'data': [{'id': ''}]}}
        }}}

        update_one = domains.domain_update(cert_obj_one)
        update_two = domains.domain_update(cert_obj_two)
        update_three = domains.domain_update(cert_obj_three)

        # should return False because `alligatorarmy.com` is not in the temp database
        assert isinstance(update_one, bool)
        assert update_one is False

        assert isinstance(update_two, bool)
        assert update_two is True

        # should return False because the domain name is missing
        assert isinstance(update_three, bool)
        assert update_three is False

