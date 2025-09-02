import logging
from unittest.mock import patch, MagicMock

from fastly import ApiException

from tlstool.secrets.aws import AWSSecretsManager
from tlstool.storage import StorageManager
secrets = AWSSecretsManager()
storage = StorageManager(secrets_plugin=secrets)


@patch("tlstool.storage.StorageManager._retrieve_pems")
@patch("tlstool.storage.StorageManager._create_pkey_record")
@patch("tlstool.storage.StorageManager._create_cert_record")
def test_load_cert_success(mock_create_cert_record, mock_create_pkey_record, mock_retrieve_pems):
    mock_retrieve_pems.return_value = ("mock-private-key", {"cert_blob": "CERT", "intermediates_blob": "INTERMEDIATES"})
    mock_create_pkey_record.return_value = {"id": "mock-key-id"}
    mock_create_cert_record.return_value = {"id": "mock-cert-id"}

    kwargs = {
        "domain": "example.com",
        "certificate_ids": [
            {"key": "private_key", "value": "secret/private/key"},
            {"key": "fullchain", "value": "secret/full/chain"}
        ]
    }
    result = storage.load_certificate(**kwargs)

    mock_retrieve_pems.assert_called_once()
    mock_create_pkey_record.assert_called_once()
    mock_create_cert_record.assert_called_once()
    assert result == {
        "pkey": {"id": "mock-key-id"},
        "cert": {"id": "mock-cert-id"}
    }

@patch("tlstool.storage.StorageManager._retrieve_pems")
@patch("tlstool.storage.StorageManager._create_pkey_record")
@patch("tlstool.storage.StorageManager._create_cert_record")
def test_load_cert_pkey_failure(mock_create_cert_record, mock_create_pkey_record, mock_retrieve_pems):
    mock_retrieve_pems.return_value = ("mock-private-key", {"cert_blob": "CERT", "intermediates_blob": "INTERMEDIATES"})
    mock_create_pkey_record.return_value = "Error: Private key already exists"

    kwargs = {
        "domain": "example.com",
        "certificate_ids": [
            {"key": "private_key", "value": "secret/private/key"},
            {"key": "fullchain", "value": "secret/full/chain"}
        ]
    }
    result = storage.load_certificate(**kwargs)

    assert result == "Error: Private key already exists"
    mock_create_cert_record.assert_not_called()  # should short-circuit before this

@patch("tlstool.storage.StorageManager._retrieve_pems")
@patch("tlstool.storage.StorageManager._create_pkey_record")
@patch("tlstool.storage.StorageManager._create_cert_record")
def test_load_cert_cert_failure(mock_create_cert_record, mock_create_pkey_record, mock_retrieve_pems):
    mock_retrieve_pems.return_value = ("mock-private-key", {"cert_blob": "CERT", "intermediates_blob": "INTERMEDIATES"})
    mock_create_pkey_record.return_value = {"id": "mock-key-id"}
    mock_create_cert_record.return_value = "Error: Cert upload failed"

    kwargs = {
        "domain": "example.com",
        "certificate_ids": [
            {"key": "private_key", "value": "secret/private/key"},
            {"key": "fullchain", "value": "secret/full/chain"}
        ]
    }
    result = storage.load_certificate(**kwargs)

    assert result == "Error: Cert upload failed"

def test_retrieve_pems_success():
    mock_secrets = MagicMock(spec_set=["get_secret_value"])
    storage = StorageManager(secrets_plugin=mock_secrets)

    mock_secrets.get_secret_value.side_effect = [
        "----PRIVATE KEY----",  # pkey
        "-----BEGIN CERT-----\n\n-----INTERMEDIATE CERT 1-----\n\n-----INTERMEDIATE CERT 2-----\n",  # fullchain
    ]
    certificate_ids = [
        {"key": "private_key", "value": "private-key-id"},
        {"key": "fullchain", "value": "fullchain-id"}
    ]

    private_key, secret_values = storage._retrieve_pems(certificate_ids)

    assert private_key == "----PRIVATE KEY----"
    assert "cert_blob" in secret_values
    assert "intermediates_blob" in secret_values
    assert "BEGIN CERT" in secret_values["cert_blob"]
    assert "-----INTERMEDIATE CERT 1-----" in secret_values["intermediates_blob"]
    assert "-----INTERMEDIATE CERT 2-----" in secret_values["intermediates_blob"]

def test_retrieve_pems_secretmanager_failure(caplog):
    caplog.set_level(logging.ERROR, logger="tlstool.storage")
    mock_secrets = MagicMock(spec_set=["get_secret_value"])
    storage = StorageManager(secrets_plugin=mock_secrets)
    mock_secrets.get_secret_value.side_effect = Exception("Secrets Manager error")

    certificate_ids = [
        {"key": "private_key", "value": "private-key-id"},
        {"key": "fullchain", "value": "fullchain-id"}
    ]

    private_key, error = storage._retrieve_pems(certificate_ids)
    assert private_key is None
    assert "Error retrieving certificate string from secrets storage" in error
    assert isinstance(error, str)
    assert "Secrets Manager error" in caplog.text

@patch("tlstool.storage.tls_private_keys_api.TlsPrivateKeysApi")
@patch("tlstool.storage.fastly.ApiClient")
@patch("tlstool.storage.fastly.Configuration")
def test_create_pkey_record_success(mock_config, mock_apiclient, mock_tls_api):
    mock_config_instance = MagicMock()
    mock_config.return_value = mock_config_instance

    mock_client_instance = MagicMock()
    mock_apiclient.return_value.__enter__.return_value = mock_client_instance

    mock_tls_api_instance = MagicMock()
    mock_tls_api.return_value = mock_tls_api_instance

    mock_tls_api_instance.create_tls_key.return_value = {"mock": "tls_key_created"}

    result = storage._create_pkey_record("exampleone.com", "fake_private_key")
    assert result == {"mock": "tls_key_created"}
    mock_tls_api_instance.create_tls_key.assert_called_once()

@patch("tlstool.storage.tls_private_keys_api.TlsPrivateKeysApi")
@patch("tlstool.storage.fastly.ApiClient")
@patch("tlstool.storage.fastly.Configuration")
def test_create_pkey_record__key_already_exists(mock_config, mock_apiclient, mock_tls_api):
    mock_config_instance = MagicMock()
    mock_config.return_value = mock_config_instance

    mock_client_instance = MagicMock()
    mock_apiclient.return_value.__enter__.return_value = mock_client_instance

    mock_tls_api_instance = MagicMock()
    mock_tls_api.return_value = mock_tls_api_instance

    error_message = "Key already exists: duplicate"
    api_exception = ApiException(http_resp=None)
    api_exception.body = error_message
    mock_tls_api_instance.create_tls_key.side_effect = lambda **kwargs: (_ for _ in ()).throw(api_exception)

    result = storage._create_pkey_record("exampleone.com", "fake_private_key")
    assert isinstance(result, str)
    assert "Private key already exists" in result

@patch("tlstool.storage.tls_private_keys_api.TlsPrivateKeysApi")
@patch("tlstool.storage.fastly.ApiClient")
@patch("tlstool.storage.fastly.Configuration")
def test_create_pkey_record_generic_api_exception(mock_config, mock_apiclient, mock_tls_api):
    mock_config_instance = MagicMock()
    mock_config.return_value = mock_config_instance

    mock_client_instance = MagicMock()
    mock_apiclient.return_value.__enter__.return_value = mock_client_instance

    mock_tls_api_instance = MagicMock()
    mock_tls_api.return_value = mock_tls_api_instance

    api_exception = ApiException(http_resp=None)
    api_exception.body = "General API error"
    mock_tls_api_instance.create_tls_key.side_effect = lambda **kwargs: (_ for _ in ()).throw(api_exception)

    result = storage._create_pkey_record("exampletwo.com", "fake_private_key")
    assert isinstance(result, str)
    assert "Exception when calling TlsPrivateKeysApi" in result

@patch("tlstool.storage.requests.request")
def test_create_cert_record_success(mock_request):
    secret_values = {
        "cert_blob": "CERT",
        "intermediates_blob": "INTERMEDIATES"
    }
    domain = "exampleone.com"

    mock_response = MagicMock()
    mock_response.json.return_value = {"status": "success"}
    mock_request.return_value = mock_response

    response = storage._create_cert_record(domain, secret_values)

    assert isinstance(response, dict)
    assert response["status"] == "success"
    mock_request.assert_called_once()

@patch("tlstool.storage.requests.request")      
def test_create_cert_record_failure(mock_request):
    secret_values = {
        "cert_blob": "CERT",
        "intermediates_blob": "INTERMEDIATES"
    }
    domain = "exampleone.com"

    error_message = "Some kind of request failure"
    mock_request.side_effect = Exception(error_message)

    response = storage._create_cert_record(domain, secret_values)

    assert isinstance(response, str)
    assert "Exception when posting cert" in response
    assert "Some kind of request failure" in response

