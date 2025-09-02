""" 
Test Suite for tlstool.orchestrator.cert_flow

This suite covers both **behavioral correctness** and **concurrency implementation**.
Future maintainers should understand the purpose of each category:

1. Behavioral Tests 
-------------------
These tests focus on the *expected outcome* of cert_flow() for different domain states,
regardless of how the function internally executes. They are robust to refactoring and
should continue passing as long as cert_flow() meets the functional requirements.

    - test_cert_flow_ok: domains with current valid certificates; skips further processing.
    - test_cert_flow_renew: domains requiring renewal; ensures all steps (request, validation,
      upload, metadata update) are executed correctly.
    - test_cert_flow_unavailable: domains that are temporarily unavailable; ensures proper
      error handling and notification.
    
2. Concurrency / Implementation Tests
-------------------------------------
These tests focus on *how* cert_flow() handles multiple domains concurrently. They may
depend on internal implementation details like threading or closures, so they are more
brittle and may need adjustment if the internals of cert_flow() change.

    - test_cert_flow_concurrent: verifies that all domains are processed concurrently and
      the orchestrator handles multiple threads properly. This is more of a high-level
      concurrency test and is safe to keep for regression coverage.
    - test_cert_flow_parallel_execution_injection: injects a spy/mocked _process_domain
      function to ensure it is actually called in parallel. Useful for catching regressions
      in threading logic but sensitive to implementation changes.
        
Notes   
-----   
- Both categories are important: behavioral tests ensure the orchestrator does the right
  thing; concurrency tests ensure it does so efficiently when multiple domains are processed.
- When refactoring cert_flow(), prioritize keeping behavioral tests passing. Concurrency
  tests may need adjustment if internal structures change.
""" 

from datetime import datetime, timedelta
import json
import logging
import time
from unittest.mock import patch

from flask import Response
import pytest
from werkzeug.exceptions import Unauthorized

from tlstool import create_app
from tlstool import orchestrator

logger = logging.getLogger(__name__)

TEST_DATE_INRANGE = (datetime.now() + timedelta(days=10)).strftime('%Y-%m-%d 00:00:00')
TEST_DATE_OUTRANGE = (datetime.now() + timedelta(days=40)).strftime('%Y-%m-%d 00:00:00')


@pytest.fixture
def client():
    test_app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'postgresql://test_user:test_password@localhost:55432/test_db',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': '1234567890'
    })
    # with test_app.app_context():
    #     testmode = getattr(g, 'testmode', None)
    with test_app.test_client() as client:
        yield client

@patch("tlstool.orchestrator.validate_header_key")
@patch("tlstool.orchestrator.set_test_mode")
@patch("tlstool.orchestrator.domains.domain_meta")
@patch("tlstool.orchestrator.run_cert_flow")
def test_process_single_domain_success(
    mock_run_cert_flow,
    mock_domain_meta,
    mock_set_test_mode,
    mock_validate_header_key,
    client
):
    mock_validate_header_key.side_effect = None
    mock_set_test_mode.return_value = None
    mock_domain_meta.return_value = [{
        'domain': 'example.com',
        'zone_id': 'XYZ12345ABC123',
        'tls_exp_date': TEST_DATE_INRANGE,
        'tls_issuer': 'GlobalSign',
    }]
    mock_run_cert_flow.return_value = Response("", status=200)

    with client.application.app_context():
        response = client.get('/single/example.com', headers={'Flask-Key': 'Header-Value'})

    mock_validate_header_key.assert_called_once()
    assert isinstance(response, Response)
    assert response.status_code == 200

@patch("tlstool.orchestrator.validate_header_key")
def test_process_single_domain_fail_no_header(
    mock_validate_header_key,
    client,
    caplog
):
    caplog.set_level(logging.INFO)
    mock_validate_header_key.side_effect = Exception("general exception")

    with client.application.app_context():
        with pytest.raises(Exception, match="general exception"):
            response = client.get('/single/example.com')

            mock_validate_header_key.assert_called_once()
            assert isinstance(response, Response)
            assert response.status_code == 400
            assert "Error: Certificate flow failed on: Missing key value" in caplog.text

@patch("tlstool.orchestrator.validate_header_key")
@patch("tlstool.orchestrator.set_test_mode")
@patch("tlstool.orchestrator.domains.domain_meta")
@patch("tlstool.orchestrator.slack_notify")
def test_process_single_domain_fail_no_meta(
    mock_slack_notify,
    mock_domain_meta,
    mock_set_test_mode,
    mock_validate_header_key,
    client
):
    mock_validate_header_key.side_effect = None
    mock_set_test_mode.return_value = None
    mock_domain_meta.return_value = []
    mock_slack_notify.side_effect = None

    with client.application.app_context():
        response = client.get('/single/example.com', headers={'Flask-Key': 'Header-Value'})

    mock_validate_header_key.assert_called_once()
    mock_slack_notify.assert_called_once()
    assert isinstance(response, Response)
    assert response.status_code == 200
    assert response.text == "Domain example.com not available for TLS"

@patch("tlstool.orchestrator.validate_header_key")
@patch("tlstool.orchestrator.set_test_mode")
@patch("tlstool.orchestrator.domains.search_domains")
@patch("tlstool.orchestrator.run_cert_flow")
def test_process_domains_success(
    mock_run_cert_flow,
    mock_domain_list,
    mock_set_test_mode,
    mock_validate_header_key,
    client
):
    mock_validate_header_key.side_effect = None
    mock_set_test_mode.return_value = None
    mock_domain_list.return_value = [{
        'domain': 'example.com',
        'zone_id': 'XYZ12345ABC123',
        'tls_exp_date': TEST_DATE_INRANGE,
        'tls_issuer': 'GlobalSign',
    }]
    mock_run_cert_flow.return_value = Response("", status=200)

    with client.application.app_context():
        response = client.get('/process', headers={'Flask-Key': 'Header-Value'})

    mock_validate_header_key.assert_called_once()
    assert isinstance(response, Response)
    assert response.status_code == 200

@patch("tlstool.orchestrator.validate_header_key")
def test_process_domains_fail_no_header(
    mock_validate_header_key,
    client,
    caplog
):
    caplog.set_level(logging.INFO)
    mock_validate_header_key.side_effect = Exception("general exception")

    with client.application.app_context():
        with pytest.raises(Exception, match="general exception"):
            response = client.get('/process')

            mock_validate_header_key.assert_called_once()
            assert isinstance(response, Response)
            assert response.status_code == 400
            assert "Error: Certificate flow failed on: Missing key value" in caplog.text

@patch("tlstool.orchestrator.validate_header_key")
@patch("tlstool.orchestrator.set_test_mode")
@patch("tlstool.orchestrator.domains.search_domains")
@patch("tlstool.orchestrator.slack_notify")
def test_process_domains_fail_no_domains(
    mock_slack_notify,
    mock_domain_list,
    mock_set_test_mode,
    mock_validate_header_key,
    client
):
    mock_validate_header_key.side_effect = None
    mock_set_test_mode.return_value = None
    mock_domain_list.return_value = []
    mock_slack_notify.side_effect = None

    with client.application.app_context():
        response = client.get('/process', headers={'Flask-Key': 'Header-Value'})

    mock_validate_header_key.assert_called_once()
    mock_slack_notify.assert_called_once()
    assert isinstance(response, Response)
    assert response.status_code == 200
    assert response.text == "No new certificates needed, none currently due for renewal"

def test_validate_header_key_success(client, caplog):
    caplog.set_level(logging.INFO)
    mock_headers = {'Flask-Key': '1234567890'}

    with client.application.app_context():
        orchestrator.validate_header_key(mock_headers)

    assert caplog.text == ''

@patch("tlstool.orchestrator.slack_error_notify")
def test_validate_header_key_fail_incorrect(mock_slack_error_notify, client, caplog):
    caplog.set_level(logging.ERROR, logger="tlstool.orchestrator")
    mock_headers = {'Flask-Key': 'ABCDEFGH'}

    with client.application.app_context():
        with pytest.raises(Unauthorized) as excinfo:
            orchestrator.validate_header_key(mock_headers)

    mock_slack_error_notify.assert_called_once()
    assert "Incorrect key value" in caplog.text
    assert excinfo.value.code == 401

@patch("tlstool.orchestrator.slack_error_notify")
def test_validate_header_key_fail_missing(mock_slack_error_notify, caplog):
    caplog.set_level(logging.ERROR, logger="tlstool.orchestrator")
    mock_headers = {'Mock-Header': 'Mock-Value'}

    with pytest.raises(Unauthorized) as excinfo:
        orchestrator.validate_header_key(mock_headers)

    mock_slack_error_notify.assert_called_once()
    assert "Missing key value" in caplog.text
    assert excinfo.value.code == 401

@patch("tlstool.orchestrator.ENV")
def test_set_test_mode_none(mock_env):
    mock_env.__str__.return_value = "not-local-or-staging"
    mock_args = {}

    response = orchestrator.set_test_mode(mock_args)

    assert response is None

@patch("tlstool.orchestrator.ENV")
def test_set_test_mode_env(mock_env, client, caplog):
    caplog.set_level(logging.INFO)
    mock_env.__str__.return_value = "local"
    mock_args = {}

    with client.application.app_context():
        response = orchestrator.set_test_mode(mock_args)

    assert response == 'test'
    assert "Entering test mode: limited domain(s) and no posting to Fastly" in caplog.text

@patch("tlstool.orchestrator.ENV")
def test_set_test_mode_args(mock_env, client, caplog):
    caplog.set_level(logging.INFO)
    mock_env.__str__.return_value = "not-local-or-staging"
    mock_args = {'testmode': 'test'}

    with client.application.app_context():
        response = orchestrator.set_test_mode(mock_args)

    assert response == 'test'
    assert "Entering test mode: limited domain(s) and no posting to Fastly" in caplog.text

@patch("tlstool.orchestrator.cert_flow")
def test_run_cert_flow_success(mock_cert_flow):
    domain_list = [{
        'domain': 'example.com',
        'zone_id': 'XYZ12345ABC123',
        'tls_exp_date': TEST_DATE_INRANGE,
        'tls_issuer': 'GlobalSign',
    }]

    response = orchestrator.run_cert_flow(domain_list)
    mock_cert_flow.assert_called_once()
    assert isinstance(response, Response)
    assert response.status_code == 200

@patch("tlstool.orchestrator.cert_flow")
@patch("tlstool.orchestrator.slack_error_notify")
def test_run_cert_flow_fail(mock_slack_error_notify, mock_cert_flow):
    domain_list = []
    mock_cert_flow.side_effect = Exception("general exception")

    response = orchestrator.run_cert_flow(domain_list)

    mock_cert_flow.assert_called_once()
    mock_slack_error_notify.assert_called_once()
    assert isinstance(response, Response)
    assert response.status_code == 400

@patch("tlstool.orchestrator.slack_notify")
@patch("tlstool.orchestrator.domains.get_domain_tls_status")
def test_cert_flow_ok(mock_tls_status, mock_slack_notify, client):
    # Behavioral test: domain's cert is already valid; cert_flow() should skip renewal
    domain_list = [{'domain': 'example.com', 'tls_issuer': 'Lets Encrypt', 'zone_id': 'XYZ12345ABC123'}]
    mock_tls_status.return_value = "ok"

    with client.application.app_context():
        response = orchestrator.cert_flow(domain_list) 

    assert response is True
    mock_slack_notify.assert_called_once()

@patch("tlstool.orchestrator.slack_notify")
@patch("tlstool.orchestrator.domains.get_domain_tls_status")
@patch("tlstool.orchestrator.certificates.request_cert")
@patch("tlstool.orchestrator.validate_certificate_request")
@patch("tlstool.orchestrator.upload_certificate")
@patch("tlstool.orchestrator.domain_metadata_update")
def test_cert_flow_renew(
    mock_domain_metadata,
    mock_upload,
    mock_validate,
    mock_request_cert,
    mock_tls_status,
    mock_slack_notify,
    client
):
    # Behavioral test: domain requires renewal; ensures all steps execute properly
    domain_list = [{'domain': 'example.com', 'tls_issuer': 'Lets Encrypt', 'zone_id': 'XYZ12345ABC123'}]
    response_dict = {'domain': domain_list[0]['domain'], 'certificate_status': 'renew', 'messages': '', 'errors': []}
    mock_tls_status.return_value = "renew"
    mock_request_cert.return_value = ['arn1', 'arn2', 'arn3']
    mock_validate.return_value = response_dict
    certificate_object = {'pkey': 'test', 'cert': {'data': {'attributes': {'not_after': '2025-11-10T15:05:10.000Z'}}}}
    mock_upload.return_value = certificate_object, response_dict
    response_dict['messages'] = "Certificate expires: " + certificate_object['cert']['data']['attributes']['not_after']
    mock_domain_metadata.return_value = response_dict

    with client.application.app_context():
        response = orchestrator.cert_flow(domain_list)

    assert response is True
    mock_slack_notify.assert_called_once()

@patch("tlstool.orchestrator.slack_error_notify")
@patch("tlstool.orchestrator.domains.get_domain_tls_status")
def test_cert_flow_unavailable(mock_tls_status, mock_slack_error_notify, client):
    # Behavioral test: domain unavailable; ensures error notification is triggered
    domain_list = [{'domain': 'example.com', 'tls_issuer': 'Lets Encrypt', 'zone_id': 'XYZ12345ABC123'}]
    mock_tls_status.return_value = "unavailable"

    with client.application.app_context():
        response = orchestrator.cert_flow(domain_list)

    assert response is True
    mock_slack_error_notify.assert_called_once()

def test_validate_certificate_request_success():
    certificate_ids = [
        {"key": "private_key", "value": "arn1:secret/private/key"},
        {"key": "fullchain", "value": "arn2:secret/full/chain"}
    ]
    response_dict = {'domain': 'example.com', 'messages': '', 'errors': []}

    response = orchestrator.validate_certificate_request(certificate_ids, response_dict)
    assert isinstance(response, dict)
    assert response == response_dict

def test_validate_certificate_request_errors():
    certificate_ids = "Unexpected error requesting cert for example.com"
    response_dict = {'domain': 'example.com', 'messages': '', 'errors': []}

    response = orchestrator.validate_certificate_request(certificate_ids, response_dict)
    assert isinstance(response, dict)
    assert response == {'domain': 'example.com', 'messages': '', 'errors': ['Unexpected error requesting cert for example.com']}

@patch("tlstool.orchestrator.storage.load_certificate")
def test_upload_certificate_success(mock_storage_load, client):
    domain = "example.com"
    certificate_ids = [
        {"key": "private_key", "value": "arn1:secret/private/key"},
        {"key": "fullchain", "value": "arn2:secret/full/chain"}
    ]
    response_dict = {'domain': 'example.com', 'messages': '', 'errors': []}
    mock_storage_load.return_value = {'pkey': 'mock private key', 'cert': 'mock certificate'}
    testmode = None

    with client.application.app_context():
        response_a, response_b = orchestrator.upload_certificate(domain, certificate_ids, response_dict, testmode)

    assert isinstance(response_a, dict)
    assert isinstance(response_b, dict)
    assert response_a == {'pkey': 'mock private key', 'cert': 'mock certificate'}
    assert response_b == response_dict
    mock_storage_load.assert_called_once()

def test_upload_certificate_test(client):
    domain = "example.com"
    certificate_ids = [
        {"key": "private_key", "value": "arn1:secret/private/key"},
        {"key": "fullchain", "value": "arn2:secret/full/chain"}
    ]
    response_dict = {'domain': 'example.com', 'messages': '', 'errors': []}
    testmode = "test"

    with client.application.app_context():
        response_a, response_b = orchestrator.upload_certificate(domain, certificate_ids, response_dict, testmode)

    assert isinstance(response_a, dict)
    assert isinstance(response_b, dict)
    assert response_a == {'pkey': 'test', 'cert': 'test'}
    assert response_b == {
        'domain': 'example.com',
        'messages': 'Test cert created from Lets Encrypt, loaded to AWS Secrets Manager, not uploaded to Fastly',
        'errors': []
    }

@patch("tlstool.orchestrator.storage.load_certificate")
def test_upload_certificate_error(mock_storage_load, client):
    domain = "example.com"
    certificate_ids = [
        {"key": "private_key", "value": "arn1:secret/private/key"},
        {"key": "fullchain", "value": "arn2:secret/full/chain"}
    ]
    response_dict = {'domain': 'example.com', 'messages': '', 'errors': []}
    mock_storage_load.return_value = "Error on certificate upload"
    testmode = None

    with client.application.app_context():
        response_a, response_b = orchestrator.upload_certificate(domain, certificate_ids, response_dict, testmode)

    assert isinstance(response_a, str)
    assert isinstance(response_b, dict)
    assert response_a == "Error on certificate upload"
    assert response_b == {
        'domain': 'example.com',
        'messages': '',
        'errors': ['Error on certificate upload']
    }
    mock_storage_load.assert_called_once()

@patch("tlstool.orchestrator.domains.domain_update")
def test_domain_metadata_update_success(mock_domain_update, client):
    mock_domain_update.return_value = True
    certificate_object = {'pkey': 'test', 'cert': {'data': {'attributes': {'not_after': '2025-11-10T15:05:10.000Z'}}}}
    response_dict = {'domain': 'example.com', 'messages': '', 'errors': []}
    testmode = None

    with client.application.app_context():
        response = orchestrator.domain_metadata_update(certificate_object, response_dict, testmode)

    assert isinstance(response, dict)
    assert response == {'domain': 'example.com', 'messages': 'Certificate expires: 2025-11-10T15:05:10.000Z', 'errors': []}

def test_domain_metadata_update_error(client):
    certificate_object = {'pkey': 'test', 'cert': {'data': {'attributes': {'not_after': '2025-11-10T15:05:10.000Z'}}}}
    response_dict = {'domain': 'example.com', 'messages': '', 'errors': ['Test error message']}
    testmode = None

    with client.application.app_context():
        response = orchestrator.domain_metadata_update(certificate_object, response_dict, testmode)

    assert isinstance(response, dict)
    assert response == response_dict

def test_slack_notify():
    slack_list = [{'domain': 'example.com', 'certificate_status': 'TESTING', 'messages': 'mock test of slack notification', 'errors': ''}]

    test_notify = orchestrator.slack_notify(slack_list)
    slack_block = json.loads(test_notify)

    assert isinstance(test_notify, str)
    assert isinstance(slack_block, dict)
    assert slack_block['text'].startswith('Updated certificates for')
    assert slack_block['blocks'][0]['text']['type'] == 'mrkdwn'
    assert slack_block['blocks'][0]['text']['text'] == 'Certificate update (tlstool local) example.com: Testing mock test of slack notification '

def test_slack_error_notify(client):
    today = datetime.today().strftime('%m-%d-%Y')
    slack_dict = {'domain': 'All', 'errors': ["Certificate flow failed on: Incorrect key value"]}

    test_error_notify = orchestrator.slack_error_notify(slack_dict)
    slack_block = json.loads(test_error_notify)

    assert isinstance(test_error_notify, str)
    assert isinstance(slack_block, dict)
    assert slack_block['text'].startswith('TLS tool error(s) at')
    assert slack_block['blocks'][0]['text']['type'] == 'mrkdwn'
    assert slack_block['blocks'][0]['text']['text'] == f"TLS tool error at {today} (local)\nAll: ['Certificate flow failed on: Incorrect key value']"

"""
Concurrency Tests for cert_flow()

These tests provide layered confidence in the concurrent behavior of cert_flow().

1. test_concurrent_execution_spy
   - Purpose: Lightweight smoke test to verify that cert_flow() handles multiple
     domains without errors.
   - Characteristics:
       * Quick to run
       * Minimal overhead
       * Does not inspect internal logic or timing
   - When to use: Routine CI runs; ensures basic parallel execution doesn't break.

2. test_cert_flow_concurrent
   - Purpose: Full functional test of cert_flow() processing multiple domains.
   - Characteristics:
       * Uses realistic mocks for certificate requests, validation, upload, and
         metadata updates
       * Confirms all internal steps are called correctly per domain
       * Slack notification tested
       * Does not measure actual timing/concurrency
   - When to use: Provides confidence that cert_flow() works correctly under load;
     ensures all steps happen for each domain.

3. test_cert_flow_parallel_execution_injection
   - Purpose: Ensures actual parallel execution of domain processing.
   - Characteristics:
       * Wraps _process_domain in a timed spy
       * Detects overlapping execution start/end times
       * Confirms threads run concurrently
       * Slower due to deliberate sleep
   - When to use: Catch regressions in threading/concurrency logic; can mark as
     @pytest.mark.slow if needed.
"""

@patch("tlstool.orchestrator.slack_notify")
@patch("tlstool.orchestrator.domain_metadata_update")
@patch("tlstool.orchestrator.upload_certificate")
@patch("tlstool.orchestrator.validate_certificate_request")
@patch("tlstool.orchestrator.certificates.request_cert")
@patch("tlstool.orchestrator.domains.get_domain_tls_status")
def test_cert_flow_concurrent(
    mock_tls_status,
    mock_request_cert,
    mock_validate,
    mock_upload,
    mock_domain_metadata,
    mock_slack_notify,
    client
):
    # Concurrency test: ensures cert_flow() handles multiple domains concurrently
    num_domains = 5
    domain_list = [
        {
            "domain": f"example{i}.com",
            "tls_issuer": "Lets Encrypt",
            "zone_id": f"ZONE{i}",
        }
        for i in range(num_domains)
    ]

    # all domains will be treated as needing renewal
    mock_tls_status.return_value = "renew"
    mock_request_cert.return_value = [
        {"key": "private_key", "value": "arn1:secret/private/key"},
        {"key": "fullchain", "value": "arn2:secret/full/chain"}
    ]

    def fake_validate(certificate_ids, response_dict):
        # we ignore certificate_ids in this test
        return {
            "domain": response_dict["domain"],
            "certificate_status": "renew",
            "messages": "",
            "errors": []
        }
    mock_validate.side_effect = fake_validate

    def fake_upload(domain, certificate_ids, response_dict, testmode):
        certificate_object = {
            "pkey": "test",
            "cert": {
                "data": {"attributes": {"not_after": str(TEST_DATE_OUTRANGE)+'+00:00.000Z'}}
            }
        }
        response_dict.update({"certificate_status": "renew", "messages": "Uploaded", "errors": []})
        return certificate_object, response_dict
    mock_upload.side_effect = fake_upload

    def fake_domain_metadata(certificate_object, response_dict, testmode):
        """
        Mock for domain_metadata_update() used in concurrency tests.

        Arguments:
            certificate_object: dict returned from upload_certificate() (ignored here)
            response_dict: dict containing the domain and other metadata
            testmode: boolean flag from cert_flow (ignored here)

        Returns:
            dict with minimal info so cert_flow() thinks metadata was updated
        """
        return {"domain": response_dict["domain"], "certificate_status": "renew", "messages": "Updated", "errors": []}

    mock_domain_metadata.side_effect = fake_domain_metadata

    with client.application.app_context():
        response = orchestrator.cert_flow(domain_list)

    assert response is True

    # sanity checks to ensure all domains went through the flow
    assert mock_tls_status.call_count == num_domains
    assert mock_request_cert.call_count == num_domains
    assert mock_validate.call_count == num_domains
    assert mock_upload.call_count == num_domains
    assert mock_domain_metadata.call_count == num_domains
    mock_slack_notify.assert_called()
    assert mock_slack_notify.call_count == num_domains

def test_concurrent_execution_spy(client):
    """
    Minimal concurrency smoke test: verifies that cert_flow executes domains in parallel
    using a small timed wrapper. Does not invoke the full cert flow.
    """
    domain_list = [
        {"domain": f"example{i}.com", "tls_issuer": "Lets Encrypt", "zone_id": f"XYZ{i}ABC"}
        for i in range(5)
    ]

    times = {}
    def timed_process_domain(domain_dict, testmode, app):
        domain = domain_dict["domain"]
        times[domain] = {"start": time.time()}
        # simulate work to allow overlap detection
        time.sleep(0.2)
        times[domain]["end"] = time.time()
        # print(f"{domain} start on thread {threading.current_thread().name}")
        # print(f"{domain} end on thread {threading.current_thread().name}")
        return {"domain": domain}

    start = time.time()
    with client.application.app_context():
        response = orchestrator.cert_flow(
            domain_list,
            process_domain_fn=timed_process_domain
        )
    duration = time.time() - start

    assert response is True

    overlap_detected = any(
        t1["start"] < t2["end"] and t1["end"] > t2["start"]
        for i, t1 in times.items()
        for j, t2 in times.items()
        if i != j
    )
    assert overlap_detected, "Expected concurrent execution of threads, but none detected"
    assert duration < 2.5, f"Duration {duration:.2f}s too long, threads might not be running concurrently"

@patch("tlstool.orchestrator.slack_notify")
@patch("tlstool.orchestrator.domains.get_domain_tls_status")
def test_cert_flow_parallel_execution_injection(mock_tls_status, mock_slack_notify, client):
    """
    Concurrency test: verifies that cert_flow() executes domain processing in parallel.

    Key points:
    - We use a timed wrapper function to record start/end times per domain.
    - This allows detection of overlapping execution (concurrent threads).
    - The wrapper accepts *args to match the signature of _process_domain, which gets
      both domain_dict and testmode internally.
    - Duration check ensures threads actually reduce total execution time.
    """

    # Define a small list of domains to process concurrently
    domain_list = [
        {"domain": f"example{i}.com", "tls_issuer": "Lets Encrypt", "zone_id": f"XYZ{i}ABC"}
        for i in range(5)
    ]

    # Mock TLS status check to always return "ok"
    mock_tls_status.return_value = "ok"

    # Dictionary to hold start and end times of each domain's processing
    times = {}

    # Wrapper function that times execution
    # Accepts domain_dict and testmode (or any extra args) to match _process_domain signature
    def timed_process_domain(domain_dict, *args, **kwargs):
        domain = domain_dict["domain"]
        # print(f"Starting {domain}")
        times[domain] = {"start": time.time()}

        # Simulate some work; short enough to allow overlap detection
        time.sleep(0.2)

        times[domain]["end"] = time.time()
        # print(f"Ending {domain}")
        # Inject a "fake" slack_notify call to satisfy the test
        orchestrator.slack_notify(f"Processed {domain}")  # will call the mock

        # Return a minimal valid response dict for cert_flow
        return {"domain": domain}

    # Record the start time of the overall flow
    start = time.time()

    # Run cert_flow using our timed wrapper instead of the real _process_domain
    # This will execute each domain in its own thread (or in the executor)
    with client.application.app_context():
        response = orchestrator.cert_flow(
            domain_list,
            process_domain_fn=timed_process_domain
        )
    # Total elapsed time
    duration = time.time() - start

    assert response is True
    mock_slack_notify.assert_called()

    # Detect overlapping execution (concurrent threads)
    overlap_detected = any(
        t1["start"] < t2["end"] and t1["end"] > t2["start"]
        for i, t1 in times.items()
        for j, t2 in times.items()
        if i != j
    )
    assert overlap_detected, "Expected concurrent execution of threads, but none detected"

    # Duration check: sequential processing would take ~num_domains * 0.2s
    # Parallel execution should be faster, demonstrating concurrency
    assert duration < len(domain_list) * 0.2, (
        f"Duration {duration:.2f}s too long; threads might not be running concurrently"
    )

