# The workflow is orchestrated from here.

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
import logging
import threading
import time

from flask import (
    abort, Blueprint, current_app, g, request, Response
)
import requests

from tlstool import settings
from tlstool.dns.aws import AWSRoute53
from tlstool.secrets.aws import AWSSecretsManager

from tlstool.certificates import CertificateManager
from tlstool.domains import DomainManager
from tlstool.storage import StorageManager

bp = Blueprint('orchestrator', __name__)
logger = logging.getLogger(__name__)

ENV = settings.FLASK_ENV

dns = AWSRoute53()
secrets = AWSSecretsManager()
certificates = CertificateManager(dns_plugin=dns, secrets_plugin=secrets)
domains = DomainManager()
storage = StorageManager(secrets_plugin=secrets)


@bp.route('/single/<string:domain>')
def process_single_domain(domain=None):
    """Process a single domain through the certificate workflow.

    Validates the request header key, optionally enables test mode, looks up metadata
    for the given domain, and either triggers the certificate flow or posts a Slack
    notification if the domain is not eligible.

    Args:
    domain (str | None): The fully qualified domain name to process, taken from
    the URL path segment.

    Returns:
    flask.Response: A 200 response with a message when the domain is not
    available for TLS. Otherwise, the response returned by
    run_cert_flow(domain_list) (typically 200 on success or 400 on failure).

    Raises:
    werkzeug.exceptions.Unauthorized: If the Flask-Key header is missing or
    incorrect (raised via validate_header_key()).

    Notes:
    - Test mode can be enabled via the testmode query parameter.
    - Sends a Slack notification when the domain is not eligible.
    - This route is registered at /single/<domain> under the orchestrator blueprint.
    """
    validate_header_key(request.headers)
    set_test_mode(request.args)
    domain_list = domains.domain_meta(domain)
    if not domain_list:
        message = f"Domain {domain} not available for TLS"
        c = [{'domain': domain, 'certificate_status': '', 'messages': message, 'errors': ''}]
        slack_notify(c)
        return Response(message, status=200)

    response = run_cert_flow(domain_list)
    return response

@bp.route("/process")
def process_domains():
    """Process a list of eligible domains through the certificate workflow.

    Validates the request header key, optionally enables test mode, retrieves the
    set of eligible domains, and either triggers the certificate flow or posts a
    Slack notification when there is nothing to process.

    Returns:
        flask.Response: A 200 response with a message when no certificates are
            due for renewal. Otherwise, the response returned by
            `run_cert_flow(domain_list)` (typically 200 on success or 400 on
            failure).

    Raises:
        werkzeug.exceptions.Unauthorized: If the `Flask-Key` header is missing
            or incorrect (raised via `validate_header_key()`).

    Notes:
        - Test mode can be enabled via the `testmode` query parameter.
        - Sends a Slack notification when there are no domains to process.
        - This route is registered at `/process` under the `orchestrator`
          blueprint.
    """
    validate_header_key(request.headers)
    set_test_mode(request.args)
    domain_list = domains.search_domains()
    if not domain_list:
        message = "No new certificates needed, none currently due for renewal"
        c = [{'domain': '', 'certificate_status': '', 'messages': message, 'errors': ''}]
        slack_notify(c)
        return Response(message, status=200)

    response = run_cert_flow(domain_list)
    return response

def validate_header_key(request_headers):
    """Validate the shared request header key and enforce access control.

    Checks the `Flask-Key` header against the application's secret key. On
    mismatch or absence, posts a Slack error notification, logs the failure, and
    aborts the request with HTTP 401.

    Args:
    request_headers (Mapping[str, str]): Incoming request headers (e.g.,
        `flask.request.headers`).

    Returns:
    None: Continues execution when the header is present and valid.

    Raises:
    werkzeug.exceptions.Unauthorized: Raised via `flask.abort(401)` when the
        header is missing or incorrect.

    Notes:
    Sends a Slack error notification on failure before aborting.
    """
    if request_headers.get('Flask-Key'):
        if request_headers['Flask-Key'] == current_app.secret_key:
            pass
        else:
            err = "Error: Certificate flow failed on: Incorrect key value"
            slack_error_notify({'domain': 'All', 'errors': [err]})
            logger.error(err)
            abort(401)
    else:
        err = "Error: Certificate flow failed on: Missing key value"
        slack_error_notify({'domain': 'All', 'errors': [err]})
        logger.error(err)
        abort(401)

def set_test_mode(request_args):
    """Enable test mode based on environment or request parameters.

    Forces test mode for `local` and `staging` environments, or enables it when
    the `testmode` query parameter is present. When enabled, sets
    `flask.g.testmode = 'test'` and logs an informational message.

    Args:
    request_args: The request argument mapping (e.g., `flask.request.args`).

    Returns:
    str | None: Returns `'test'` when test mode is enabled; otherwise `None`.

    Notes:
    Test mode limits the domains processed and prevents posting to Fastly.
    """
    testmode = None
    if str(ENV) in ('local', 'staging'):
        testmode = 'test'
    else:
        testmode = request_args.get('testmode')
    if testmode:
        g.testmode = 'test'
        logger.info("Entering test mode: limited domain(s) and no posting to Fastly")
    return testmode

def run_cert_flow(domain_list):
    """Run the certificate flow and return an HTTP response.

    Executes the `cert_flow` pipeline for the provided domains and converts the
    outcome into an HTTP response: 200 on success, 400 on failure. On error,
    posts a Slack error notification before returning the failure status.

    Args:
    domain_list (list[dict]): Iterable of domain metadata dicts to process.

    Returns:
    flask.Response: An empty response with status 200 if the flow completes
        successfully; otherwise an empty response with status 400.

    Notes:
    All exceptions raised by `cert_flow` are caught, logged, and reported to
    Slack; this function itself does not re-raise.
    """
    try:
        cert_flow(domain_list)
        status = 200
    except Exception as e:
        message = f"Certificate flow failed on: {e}"
        slack_error_notify({'domain': 'All', 'errors': [message]})
        status = 400
    return Response("", status=status)

def cert_flow(domain_list, process_domain_fn=None):
    """Process domains through the certificate issuance/renewal pipeline.

    For each domain this function:
    1. Check TLS to determine if a new/renewed certificate is required.
    2. If required, request a certificate with Let’s Encrypt (ACME).
    3. Store the certificate and private key in AWS Secrets Manager.
    4. Upload the certificate/private key to Fastly.
    5. Update the domain database to indicate `ssl_created`.

    Domains are processed concurrently via a `ThreadPoolExecutor`, with
    per-domain thread names for clearer logs. Per-domain processing time is
    recorded. An optional `process_domain_fn` can be injected for testing/mocking.

    Args:
    domain_list (list[dict]): Iterable of domain metadata dicts to process.
    process_domain_fn (Callable[[dict, str | None, flask.Flask], dict] | None):
        Optional replacement for the internal per-domain worker; primarily
        used for tests or mocks. If provided, it must accept arguments
        `(domain_dict, testmode, app)` and return a per-domain result dict.

    Returns:
    bool: `True` after all submitted domain tasks have completed.
    """
    testmode = getattr(g, 'testmode', None)
    app = current_app._get_current_object()  # capture the real app instance

    def _process_domain(d, testmode, app):
        start_time = time.time()
        domain = d['domain'].lower()
        response_dict = {'domain': domain, 'messages': '', 'errors': []}

        thread_name = f"Domain-{domain}"
        original_thread_name = threading.current_thread().name
        threading.current_thread().name = thread_name

        try:
            with app.app_context():

                logger.info(f"[{thread_name}] Starting processing for domain: {domain}")

                tls_issuer = d['tls_issuer']
                zone_id = d['zone_id']

                certificate_status = domains.get_domain_tls_status(domain, tls_issuer)

                if certificate_status == 'ok':
                    response_dict['certificate_status'] = certificate_status
                    response_dict['messages'] = f"Not due for renewal: {domain}"
                elif certificate_status in ('new', 'renew'):
                    response_dict['certificate_status'] = certificate_status
                    certificate_ids = certificates.request_cert(
                        domain=domain,
                        zone_id=zone_id
                    )
                    response_dict = validate_certificate_request(certificate_ids, response_dict)
                    certificate_object, response_dict = upload_certificate(domain, certificate_ids, response_dict, testmode)
                    response_dict = domain_metadata_update(certificate_object, response_dict, testmode)
                else:
                    response_dict['certificate_status'] = 'unavailable'
                    response_dict['errors'].append(certificate_status)

                if response_dict['errors']:
                    logger.info(f"[{thread_name}] Errors on {domain}: {response_dict['errors']}")
                    slack_error_notify(response_dict)
                else:
                    logger.info(f"[{thread_name}] Successfully processed {domain}")
                    slack_notify([response_dict])

        except Exception as e:
            logger.exception(f"[{thread_name}] Unexpected error processing {domain}: {e}")
            response_dict['errors'].append(str(e))
            slack_error_notify(response_dict)

        finally:
            duration = time.time() - start_time
            logger.info(f"[{thread_name}] Finished processing for domain: {domain} (took {duration:.2f}s)")
            threading.current_thread().name = original_thread_name

        return response_dict

    # Use injected function if provided
    _process_domain_to_use = process_domain_fn or _process_domain

    max_workers = min(5, len(domain_list))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_process_domain_to_use, d, testmode, app) for d in domain_list]
        for future in as_completed(futures):
            future.result()

    return True

def validate_certificate_request(certificate_ids, response_dict):
    """Append certificate request errors to the response accumulator.

    Interprets a string `certificate_ids` value as an error message and appends
    it to `response_dict['errors']`. Non-string values are treated as success
    and leave the response unchanged.

    Args:
    certificate_ids (Any): Result from the certificate request step. A
        string is treated as an error message; other types indicate success.
    response_dict (dict): Mutable response accumulator containing an
        `'errors'` list.

    Returns:
    dict: The updated `response_dict` (same object), potentially with the
        error message appended.

    Notes:
    This function mutates `response_dict` in place.
    """
    if isinstance(certificate_ids, str):
        response_dict['errors'].append(certificate_ids)
    return response_dict

def upload_certificate(domain, certificate_ids, response_dict, testmode):
    """Load or synthesize a certificate object and update the response.

    When no prior errors exist, either synthesizes a test certificate object in
    test mode or loads certificate material via storage for the given domain and
    identifiers. Any non-dict result or value containing the substring "Error"
    is treated as a failure and appended to `response_dict['errors']`.

    Args:
        domain (str): The fully qualified domain name being processed.
        certificate_ids (Any): Identifiers or metadata needed by storage to
            load the certificate (type is storage-implementation specific).
        response_dict (dict): Mutable response accumulator containing `'errors'`
            and `'messages'` fields.
        testmode (Any): Truthy value enables test behavior (no external upload).

    Returns:
        tuple[dict | None, dict]: A tuple of `(certificate_object, response_dict)`,
            where `certificate_object` is a dict in success or `None` if not set,
            and `response_dict` is the (mutated) accumulator.
    """
    certificate_object = None
    if not response_dict['errors']:
        if testmode:
            certificate_object = {'pkey': 'test', 'cert': 'test'}
            response_dict['messages'] += "Test cert created from Lets Encrypt, loaded to AWS Secrets Manager, not uploaded to Fastly"
        else:
            certificate_object = storage.load_certificate(domain, certificate_ids)
        if (not isinstance(certificate_object, dict)) or ('Error' in str(certificate_object)):
            response_dict['errors'].append(str(certificate_object))
    return certificate_object, response_dict

def domain_metadata_update(certificate_object, response_dict, testmode):
    """Update domain metadata in storage based on certificate details.

    In test mode, synthesizes a fake certificate payload (with fixed validity
    dates and a wildcard domain relationship), logs the action, and updates the
    domain record without performing any external uploads. Outside test mode,
    when no prior errors exist, sets a human-readable expiration message on the
    response and updates the domain record using the provided certificate
    object.

    Args:
        certificate_object (dict | None): Certificate payload expected to include
            `cert.data.attributes.not_after` when not in test mode. Ignored in
            test mode, where a synthetic object is created.
        response_dict (dict): Mutable response accumulator containing an `'errors'`
            list and a `'messages'` field that may be updated.
        testmode (Any): Truthy value enables test behavior and synthetic metadata.

    Returns:
        dict: The (potentially mutated) `response_dict` after updating messages
            and persisting domain metadata.

    Notes:
    - Persists changes via `domains.domain_update(...)`.
    - Logs when operating in test mode.
    """
    if testmode:
        domain = response_dict.get('domain', 'example.com')

        data = {
            'id': f'FAKE-{domain}',
            'attributes': {
                'not_after': '2099-01-01T00:00:00Z',
                'not_before': '2025-01-01T00:00:00Z',
                'created_at': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            'relationships': {
                'tls_domains': {'data': [{'id': f'*.{domain}'}]}
            }
        }
        certificate_object = {'cert': {'data': data}}
        logger.info(f"Test mode, updating DB only for {domain}")
        domains.domain_update(certificate_object)
        return response_dict

    if not response_dict['errors']:
        response_dict['messages'] = "Certificate expires: " + certificate_object['cert']['data']['attributes']['not_after']
        domains.domain_update(certificate_object)
    return response_dict

def slack_notify(slack_list):
    """Send a Slack notification summarizing a full certificate run.

    Always builds the Slack block. Sends only in production when
    ENABLE_SLACK_NOTIFICATIONS is true and webhook creds are present.
    Otherwise, logs the JSON payload and returns it.

    Args:
        slack_list (list[dict]): A list of per-domain result dictionaries,
            each containing `domain`, `certificate_status`, `messages`, and
            `errors`.

    Returns:
        str: The Slack API response text when posting in production, otherwise
            the JSON payload string that was logged and would be sent.
    """
    t = datetime.today()
    today = t.strftime('%m-%d-%Y')
    section_text = f"Certificate update (tlstool {ENV}) "
    section_text += '\n'.join([ f"{x['domain']}: {x['certificate_status'].title()} {x['messages']} {x['errors']}" for x in slack_list ])
    slack_block = {
        "text": f"Updated certificates for {today} ({ENV})",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": section_text}}
        ]
    }
    payload = json.dumps(slack_block)

    if ENV != "production" or not getattr(settings, "ENABLE_SLACK_NOTIFICATIONS", False):
        logger.info(f"[Slack disabled] Slack Error Payload: {payload}")
        return payload

    slack_key = getattr(settings, "SLACK_WEBHOOK_KEY", None)
    slack_ws = getattr(settings, "SLACK_WORKSPACE_ID", None)

    if not slack_key or not slack_ws:
        logger.warning(
            "Slack notifications enabled but SLACK_WEBHOOK_KEY/SLACK_WORKSPACE_ID are missing. "
            "Logging payload instead."
        )
        logger.info(f"Slack Payload: {payload}")
        return payload

    slack_webhook = f"https://hooks.slack.com/services/{slack_ws}/{slack_key}"

    try:
        r = requests.post(
            slack_webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        r.raise_for_status()
        return r.text
    except requests.RequestException as e:
        logger.exception("Slack post failed; logging payload instead.")
        logger.info(f"Slack Error Payload: {payload}")
        return str(e)

def slack_error_notify(slack_dict):
    """Send a Slack notification for a single fatal error.
    
    Always builds the Slack block. Sends only in production when
    ENABLE_SLACK_NOTIFICATIONS is true and webhook creds are present.
    Otherwise, logs the JSON payload and returns it.
    
    Args:
    slack_dict (dict): Error context containing at least:
        - 'domain' (str): The domain associated with the error.
        - 'errors' (Any): Error details to include in the message.
    
    Returns:
    str: The Slack API response text when posting in production; otherwise
        the JSON payload string that was logged and would be sent.
    """
    t = datetime.today()
    today = t.strftime("%m-%d-%Y")
    section_text = f"TLS tool error at {today} ({ENV})\n"
    section_text += f"{slack_dict['domain']}: {slack_dict['errors']}"
    slack_block = {
        "text": f"TLS tool error(s) at ({ENV})",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": section_text}}
        ],
    }
    payload = json.dumps(slack_block)

    if ENV != "production" or not getattr(settings, "ENABLE_SLACK_NOTIFICATIONS", False):
        logger.info(f"[Slack disabled] Slack Error Payload: {payload}")
        return payload

    slack_key = getattr(settings, "SLACK_WEBHOOK_KEY", None)
    slack_ws = getattr(settings, "SLACK_WORKSPACE_ID", None)

    if not slack_key or not slack_ws:
        logger.warning(
            "Slack notifications enabled but SLACK_WEBHOOK_KEY/SLACK_WORKSPACE_ID are missing. "
            "Logging payload instead."
        )
        logger.info(f"Slack Error Payload: {payload}")
        return payload

    slack_webhook = f"https://hooks.slack.com/services/{slack_ws}/{slack_key}"

    try:
        r = requests.post(
            slack_webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        r.raise_for_status()
        return r.text
    except requests.RequestException as e:
        logger.exception("Slack post failed; logging payload instead.")
        logger.info(f"Slack Error Payload: {payload}")
        return str(e)
