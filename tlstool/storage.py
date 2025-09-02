# methods for making Fastly API calls

import json
import logging

import fastly
from fastly.api import tls_private_keys_api
from flask import Blueprint
import requests

from tlstool import settings
from tlstool.secrets import SecretsBase

bp = Blueprint('storage', __name__)
logger = logging.getLogger(__name__)

class StorageManager:

    def __init__(self, secrets_plugin: SecretsBase):
        """Initialize the storage manager with secrets and Fastly configuration.

        Stores the provided secrets plugin and loads Fastly configuration values
        from application settings for use in certificate upload and retrieval.

        Args:
            secrets_plugin (SecretsBase): Secrets management plugin used to read
                certificate material (PEMs) and related identifiers.

        Returns:
            None
        """
        self.secrets = secrets_plugin 
        self.api_token = settings.FASTLY_API_TOKEN
        self.fastly_tls_configuration_id = settings.FASTLY_TLS_CONFIGURATION_ID

    def load_certificate(self, domain, certificate_ids):
        """Upload certificate materials to Fastly and return upload results.

        Retrieves PEM materials using the provided identifiers, creates a private key
        in Fastly, then creates a certificate in Fastly referencing the uploaded key.
        If any step fails, an error string is returned; otherwise a result object is
        returned containing both upload responses.

        Args:
            domain (str): The fully qualified domain name associated with the
                certificate.
            certificate_ids (Any): Identifiers required to retrieve PEM materials
                from the secrets backend (implementation-specific; typically ARNs or
                similar handles).

        Returns:
            dict | str: On success, a dict with:
                {
                    'pkey': <private key upload response>,
                    'cert': <certificate upload response>
                }
                On failure, a string describing the error.
        """
        private_key, secret_values = self._retrieve_pems(certificate_ids)
        if private_key is None:
            return secret_values  # This will be an error message string

        pkey_upload = self._create_pkey_record(domain, private_key)
        if 'Error' in str(pkey_upload):
            logger.info(f"Error on private key upload to Fastly: {str(pkey_upload)}")
            return str(pkey_upload)
        else:
            logger.info("Private key uploaded to Fastly")

        cert_upload = self._create_cert_record(domain, secret_values)
        if 'Error' in str(cert_upload):
            logger.info(f"Error on certificate upload to Fastly: {str(cert_upload)}")
            return str(cert_upload)
        else:
            logger.info("Certificate uploaded to Fastly")

        upload_obj = {'pkey': pkey_upload, 'cert': cert_upload}
        return upload_obj

    def _retrieve_pems(self, certificate_ids):
        """Retrieve PEM materials from secrets storage using provided identifiers.

        Parses the given identifiers to locate the private key and full-chain
        certificate entries, fetches their values from the secrets backend, and
        returns a tuple of the private key and a dict containing the certificate
        and intermediate bundle blobs. On retrieval failure, returns `(None,
        <error_string>)`.

        Args:
            certificate_ids (list[dict]): Iterable of items produced by the
                certificate request flow, each with:
                - 'key' (str): Logical name; expected values include
                  'private_key' and 'fullchain'.
                - 'value' (str): Backend-specific identifier for the secret
                  (e.g., an ARN or secret name).

        Returns:
            tuple[str | None, dict | str]:
                - On success: `(private_key, {'cert_blob': str, 'intermediates_blob': str})`.
                - On error: `(None, 'Error message string')`.
        """
        secret_id = ''
        pkey_id = ''
        for c in certificate_ids:
            if c['key'] == 'fullchain':
                secret_id = c['value']
            if c['key'] == 'private_key':
                pkey_id = c['value']

        private_key = ''
        if pkey_id:
            try:
                private_key = self.secrets.get_secret_value(pkey_id)
            except Exception as e:
                error = f"Error retrieving certificate string from secrets storage: {e}"
                logger.exception(error)
                return None, error

        secret_values = {}
        if secret_id:
            try:
                secret_str = self.secrets.get_secret_value(secret_id)
                secret_values['cert_blob'] = secret_str.split('\n\n')[0]
                intermediates = ('\n\n').join(secret_str.split('\n\n')[1:3])
                if intermediates.endswith('\n'):
                    intermediates = intermediates[:-(len('\n'))]
                secret_values['intermediates_blob'] = intermediates
            except Exception as e:
                error = f"Error retrieving certificate string from secrets storage: {e}"
                logger.exception(error)
                return None, error

        return private_key, secret_values

    def _create_pkey_record(self, domain, pkey):
        """Create a TLS private key record in Fastly.

        Authenticates with the Fastly API using the configured token and creates a
        new TLS private key resource associated with the given domain. If the key
        already exists or an API error occurs, returns an error string.

        Args:
            domain (str): The fully qualified domain name the key is associated with.
            pkey (str): PEM-encoded private key content.

        Returns:
            Any | str: The Fastly API response object on success; otherwise an error
                string describing the failure.
        """
        configuration = fastly.Configuration()
        configuration.api_token = self.api_token

        with fastly.ApiClient(configuration) as api_client:
            api_instance = tls_private_keys_api.TlsPrivateKeysApi(api_client)
            options = {
                'tls_private_key': {
                    'data': {
                        'type': 'tls_private_key',
                        'attributes': {
                            'key': pkey,
                            'name': f'{domain} private key',
                        },
                    },
                },
            }

            try:
                api_response = api_instance.create_tls_key(**options)
                logger.info(f"Fastly API Response on create key: {api_response}")
            except fastly.ApiException as e:
                if "Key already exists" in str(e):
                    err = f"Error: Private key already exists: {e}"
                    logger.exception(err)
                    return err
                else:
                    err = f"Error: Exception when calling TlsPrivateKeysApi->create_tls_key: {e}"
                    logger.exception(err)
                    return err

        return api_response

    def _create_cert_record(self, domain, secret_values):
        """Create a TLS certificate record in Fastly via the bulk certificates API.

        Builds a bulk certificate payload using the provided certificate and
        intermediates blobs, associates it with the configured TLS configuration,
        and POSTs it to Fastly. Returns the parsed JSON response on success or an
        error string on failure.

        Args:
            domain (str): The fully qualified domain name the certificate pertains to.
            secret_values (dict): Dictionary containing:
                - 'cert_blob' (str): PEM-encoded end-entity certificate (no key).
                - 'intermediates_blob' (str): PEM-encoded intermediate chain.

        Returns:
            dict | str: Parsed JSON response from Fastly on success; otherwise an
                error string describing the failure.
        """
        url = "https://api.fastly.com/tls/bulk/certificates"

        options = {"data": {
            "type": "tls_bulk_certificate",
            "attributes": {"allow_untrusted_root": True, "cert_blob": secret_values['cert_blob']+"\n", "intermediates_blob": secret_values['intermediates_blob']+"\n"},
            "relationships": {"tls_configurations": {"data": [{"type": "tls_configuration", "id": self.fastly_tls_configuration_id}]}}
        }}
        payload = json.dumps(options)

        headers = {
            'Host': 'api.fastly.com',
            'Content-Type': 'application/vnd.api+json',
            'Accept': 'application/vnd.api+json',
            'Fastly-Key': self.api_token
        }
        try:
            response = requests.request("POST", url, headers=headers, data=payload)
            api_response = response.json()
            logger.info(f"Fastly API Response on create cert: {api_response}")
        except Exception as e:
            err = f"Error: Exception when posting cert object: {e}"
            logger.exception(err)
            return err

        return api_response
