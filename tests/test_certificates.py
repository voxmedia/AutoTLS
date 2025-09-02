import logging
from unittest.mock import patch, MagicMock

from acme import errors
from acme import challenges
import pytest

from tlstool.dns import DNSBase
from tlstool.dns.aws import AWSRoute53
from tlstool.secrets.aws import AWSSecretsManager
from tlstool.certificates import CertificateManager

dns = AWSRoute53()
secrets = AWSSecretsManager()
certificates = CertificateManager(dns_plugin=dns, secrets_plugin=secrets)

logger = logging.getLogger(__name__)


@patch("tlstool.certificates.CertificateManager._store_cert_materials", autospec=True)
@patch("tlstool.certificates.CertificateManager._finalize_acme_order", autospec=True)
@patch("tlstool.certificates.CertificateManager._update_dns", autospec=True)
@patch("tlstool.certificates.CertificateManager._prepare_dns_challenges", autospec=True)
@patch("tlstool.certificates.CertificateManager._begin_acme_order", autospec=True)
def test_request_cert_success(
    mock_begin, mock_prepare, mock_update, mock_finalize, mock_store
):
    kwargs = {'domain': 'example.com', 'zone_id': 'XYZ12345ABC123'}
    mock_begin.return_value = ("client_acme", "order_object", "pkey_pem", "csr_pem")
    mock_prepare.return_value = [[1, 2, 3]]
    mock_update.return_value = True
    mock_finalize.return_value = "fullchain_pem"
    mock_store.return_value = ["arn1", "arn2", "arn3"]

    mock_dns = MagicMock()
    mock_secrets = MagicMock()

    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    result = cm.request_cert(**kwargs)

    assert result == ['arn1', 'arn2', 'arn3']
    assert isinstance(result, list)

@patch("tlstool.certificates.CertificateManager._store_cert_materials", autospec=True)
@patch("tlstool.certificates.CertificateManager._finalize_acme_order", autospec=True)
@patch("tlstool.certificates.CertificateManager._update_dns", autospec=True)
@patch("tlstool.certificates.CertificateManager._prepare_dns_challenges", autospec=True)
@patch("tlstool.certificates.CertificateManager._begin_acme_order", autospec=True)
def test_request_cert_success_no_previous(
    mock_begin, mock_prepare, mock_update, mock_finalize, mock_store
):
    kwargs = {'domain': 'example.com', 'zone_id': 'XYZ12345ABC123'}
    mock_begin.return_value = ("client_acme", "order_object", "pkey_pem", "csr_pem")
    mock_prepare.return_value = [[1, 2, 3]]
    mock_update.return_value = True
    mock_finalize.return_value = "fullchain_pem"
    mock_store.return_value = ['arn1', 'arn2', 'arn3']

    mock_dns = MagicMock()
    mock_secrets = MagicMock()

    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    result = cm.request_cert(**kwargs)

    assert isinstance(result, list)
    assert result == ['arn1', 'arn2', 'arn3']

@patch("tlstool.certificates.CertificateManager._begin_acme_order", autospec=True)
@patch("tlstool.certificates.CertificateManager._prepare_dns_challenges", autospec=True)
@patch("tlstool.certificates.CertificateManager._update_dns", autospec=True)
def test_request_cert_failed_dns_update(
    mock_update, mock_prepare, mock_begin
):
    kwargs = {'domain': 'example.com', 'zone_id': 'XYZ12345ABC123'}
    mock_begin.return_value = "client_acme", "order_object", "pkey_pem", "csr_pem"
    mock_prepare.return_value = [[1, 2, 3]]
    mock_update.return_value = False

    mock_dns = MagicMock()
    mock_secrets = MagicMock()

    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    result = cm.request_cert(**kwargs)

    assert isinstance(result, str)
    assert result == "Error: DNS update failed for example.com"

@patch("tlstool.certificates.CertificateManager._begin_acme_order", autospec=True)
@patch("tlstool.certificates.CertificateManager._prepare_dns_challenges", autospec=True)
@patch("tlstool.certificates.CertificateManager._update_dns", autospec=True)
@patch("tlstool.certificates.CertificateManager._finalize_acme_order", autospec=True)
def test_request_cert_failed_finalize(
    mock_finalize, mock_update,  mock_prepare, mock_begin
):
    kwargs = {'domain': 'example.com', 'zone_id': 'XYZ12345ABC123'}
    mock_begin.return_value = "client_acme", "order_object", "pkey_pem", "csr_pem"
    mock_prepare.return_value = [[1, 2, 3]]
    mock_update.return_value = True
    mock_finalize.return_value = "Error: Answer challenge exception for example.com"

    result = certificates.request_cert(**kwargs)
    assert isinstance(result, str)
    assert result == "Error: Answer challenge exception for example.com"

@patch("tlstool.certificates.CertificateManager._begin_acme_order")
def test_request_cert_failed_exception(mock_begin):
    kwargs = {'domain': 'example.com', 'zone_id': 'XYZ12345ABC123'}
    mock_begin.side_effect = Exception('generic exception')

    result = certificates.request_cert(**kwargs)
    assert isinstance(result, str)
    assert result == "Unexpected error requesting cert for example.com: generic exception"

@patch("tlstool.certificates.CertificateManager._new_csr")
@patch("tlstool.certificates.ClientV2")
@patch("tlstool.certificates.messages.Directory.from_json")
@patch("tlstool.certificates.ClientNetwork")
@patch("tlstool.certificates.josepy.JWKRSA.fields_from_json")
def test_begin_acme_order(
    mock_fields_from_json,
    mock_client_network,
    mock_directory_from_json,
    mock_clientv2,
    mock_new_csr
):
    mock_user_key = MagicMock()
    mock_pubkey = MagicMock()
    mock_user_key.public_key.return_value = mock_pubkey
    mock_fields_from_json.return_value = mock_user_key

    mock_net = MagicMock()
    mock_client_network.return_value = mock_net
    mock_net.get.return_value.json.return_value = {"directory": "info"}

    mock_directory = {"newAccount": "https://example.com/acct"}
    mock_directory_from_json.return_value = mock_directory

    mock_client = MagicMock()
    mock_clientv2.return_value = mock_client
    mock_response = MagicMock()
    mock_regr = MagicMock()
    mock_order = MagicMock()

    mock_client._post.return_value = mock_response
    mock_client._regr_from_response.return_value = mock_regr
    mock_client.query_registration.return_value = None
    mock_client.new_order.return_value = mock_order

    mock_pkey = b"mock_private_key"
    mock_csr = b"mock_csr"
    mock_new_csr.return_value = (mock_pkey, mock_csr)

    mock_dns = MagicMock()
    mock_secrets = MagicMock()
    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    mock_secrets.get_secret_value.return_value = '{"kty": "RSA", "n": "some_modulus", "e": "AQAB"}'

    result_client, result_order, result_pkey, result_csr = cm._begin_acme_order("example.com")

    assert result_client == mock_client
    assert result_order == mock_order
    assert result_pkey == mock_pkey
    assert result_csr == mock_csr

@patch("tlstool.certificates.CertificateManager._get_dns_challenge")
def test_prepare_dns_challenges(mock_dns_challenge):
    mock_client_acme = MagicMock()
    mock_client_acme.net.key.return_value = "key"

    mock_order_obj = MagicMock()

    mock_challenge_obj = MagicMock()
    mock_challenge_obj.response_and_validation.return_value = ("mock_response", "mock_validation")

    mock_dns_challenge.return_value = [mock_challenge_obj]

    result = certificates._prepare_dns_challenges(mock_client_acme, mock_order_obj)
    assert isinstance(result, list)
    assert isinstance(result[0], list)
    assert result[0] == [mock_challenge_obj, "mock_response", "mock_validation"]

def test_finalize_acme_order_success():
    mock_finalized_order = MagicMock()
    mock_finalized_order.fullchain_pem = "fullchain PEM"

    mock_client_acme = MagicMock()
    mock_client_acme.answer_challenge.return_value = "challenge resource"
    mock_client_acme.poll_and_finalize.return_value = mock_finalized_order

    mock_order_object = MagicMock()
    mock_dns_data = [[1, 2, 3]]  # any values, as long as there are three of them

    result = certificates._finalize_acme_order(mock_client_acme, mock_order_object, mock_dns_data, "example.com")
    assert isinstance(result, str)
    assert result == "fullchain PEM"

def test_finalize_acme_order_validation_error():
    mock_client_acme = MagicMock()
    mock_order_object = MagicMock()
    mock_dns_data = [[1, 2, 3]]  # challb, response, _

    # Create a mock ValidationError with failed_authzrs attribute
    mock_validation_error = errors.ValidationError("bad authz")
    mock_validation_error.failed_authzrs = ["authz failure"]

    mock_client_acme.answer_challenge.side_effect = mock_validation_error

    result = certificates._finalize_acme_order(mock_client_acme, mock_order_object, mock_dns_data, "example.com")
    assert result == "Error validating domain example.com. See logs for details."

def test_finalize_acme_order_generic_exception():
    mock_client_acme = MagicMock()
    mock_order_object = MagicMock()
    mock_dns_data = [[1, 2, 3]]

    mock_client_acme.answer_challenge.side_effect = Exception("general exception")

    result = certificates._finalize_acme_order(mock_client_acme, mock_order_object, mock_dns_data, "example.com")
    assert result == "Error: Answer challenge exception for example.com: general exception"

@patch("tlstool.certificates.CertificateManager._store_pems")
def test_store_cert_materials_success(mock_store_pems):
    mock_store_pems.return_value = ['arn1', 'arn2', 'arn3']
    domain = "example.com"
    pkey_pem = "private key"
    csr_pem = "signing request"
    fullchain_pem = "full chain"

    result = certificates._store_cert_materials(domain, pkey_pem, csr_pem, fullchain_pem)
    assert isinstance(result, list)
    assert len(result) == 3
    assert result[0] == "arn1"

@patch("tlstool.certificates.CertificateManager._store_pems")
def test_store_cert_materials_error(mock_store_pems):
    domain = "example.com"
    pkey_pem = "private key"
    csr_pem = "signing request"
    fullchain_pem = "full chain"

    mock_store_pems.side_effect = Exception("general exception")

    result = certificates._store_cert_materials(domain, pkey_pem, csr_pem, fullchain_pem)
    assert result == "Error storing certificate for example.com: general exception"

@patch("tlstool.certificates.crypto_util.make_csr")
@patch("tlstool.certificates.crypto.PKey")
def test_new_csr_generates_key_and_csr(mock_pkey, mock_make_csr):
    pkey_mock = MagicMock()
    mock_pkey.return_value = pkey_mock
    pkey_mock.generate_key.return_value = None
    pkey_mock_data = b"mock_private_key"
    mock_make_csr.return_value = b"mock_csr"

    with patch("tlstool.certificates.crypto.dump_privatekey", return_value=pkey_mock_data):
        key, csr = certificates._new_csr("example.com")
        assert key == b"mock_private_key"
        assert csr == b"mock_csr"

def test_get_dns_challenge_success():
    mock_order_obj = MagicMock()
    mock_item = MagicMock()
    mock_object = MagicMock()
    mock_object.chall = challenges.DNS01()
    mock_item.body.challenges = [mock_object]
    mock_order_obj.authorizations = [mock_item]

    result = certificates._get_dns_challenge(mock_order_obj)
    assert isinstance(result, list)

def test_get_dns_challenge_error(caplog):
    caplog.set_level(logging.INFO)

    mock_order_obj = MagicMock()
    mock_order_obj.authorizations = []

    result = certificates._get_dns_challenge(mock_order_obj)
    assert result == []
    assert "DNS-01 challenge was not offered by the CA server." in caplog.text

@patch("tlstool.certificates.CertificateManager._apply_dns_change")
def test_update_dns_success(mock_apply_dns_change, caplog):
    caplog.set_level(logging.INFO)
    mock_apply_dns_change.return_value = True

    tokens = ['123', '456', '789']
    domain = "example.com"
    zone_id = "XYZ12345ABC123"

    mock_dns = MagicMock(spec_set=["clear_old_acme_txt", "build_domain_validation_record"])
    mock_secrets = MagicMock()
    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    mock_dns.clear_old_acme_txt.return_value = True
    mock_dns.build_domain_validation_record.return_value = {}

    result = cm._update_dns(tokens, domain, zone_id)
    assert isinstance(result, bool)
    assert result is True
    assert "DNS update complete for example.com" in caplog.text

@patch("tlstool.certificates.CertificateManager._apply_dns_change")
def test_update_dns_error(mock_apply_dns_change, caplog):
    caplog.set_level(logging.INFO)
    mock_apply_dns_change.return_value = True

    tokens = ['123', '456', '789']
    domain = "example.com"
    zone_id = "XYZ12345ABC123"

    mock_dns = MagicMock(spec_set=["clear_old_acme_txt", "build_domain_validation_record"])
    mock_secrets = MagicMock()
    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    mock_dns.clear_old_acme_txt.side_effect = Exception("general exception")
    mock_dns.build_domain_validation_record.return_value = {}

    result = cm._update_dns(tokens, domain, zone_id)
    assert "Error clearing older acme challenge for example.com: general exception" in caplog.text
    assert isinstance(result, bool)
    assert result is True

def test_store_pems_success():
    domain = 'example.com',
    pem_list = [{'value': b'bytes object', 'key': 'pem-key'}]

    mock_dns = MagicMock()
    mock_secrets = MagicMock(spec_set=["store_pem_secret"])
    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    mock_secrets.store_pem_secret.return_value = 'arn-id'

    result = cm._store_pems(domain, pem_list)
    assert isinstance(result, list)
    assert result == [{'key': 'pem-key', 'value': 'arn-id'}]

def test_apply_dns_change_success():
    record = "any string"

    mock_dns = MagicMock(spec_set=["change_dns"])
    mock_secrets = MagicMock()
    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    mock_dns.change_dns.return_value = True

    result = cm._apply_dns_change(record)
    mock_dns.change_dns.assert_called_once()
    assert result is None

def test_apply_dns_change_error(caplog):
    caplog.set_level(logging.ERROR, logger="tlstool.certificates")
    record = {'RRSet': {'Name': 'rrset name'}}

    mock_dns = MagicMock(spec_set=["change_dns"])
    mock_secrets = MagicMock()

    cm = CertificateManager(dns_plugin=mock_dns, secrets_plugin=mock_secrets)
    mock_dns.change_dns.side_effect = DNSBase.DNSError("generic exception")

    with pytest.raises(DNSBase.DNSError, match="generic exception"):
        cm._apply_dns_change(record)

    mock_dns.change_dns.assert_called_once()
    assert "Error: DNS change failed for rrset name: generic exception" in caplog.text
