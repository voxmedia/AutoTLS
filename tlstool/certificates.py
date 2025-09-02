# methods for making certbot calls for Let's Encrypt

import datetime
import json
import logging
from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM

from acme import challenges, crypto_util
from acme import errors, messages
from acme.client import ClientNetwork, ClientV2
from flask import Blueprint
import josepy

from tlstool import settings
from tlstool.dns import DNSBase
from tlstool.secrets import SecretsBase

bp = Blueprint('certificates', __name__)
logger = logging.getLogger(__name__)

class CertificateManager:

    def __init__(self, dns_plugin: DNSBase, secrets_plugin: SecretsBase):
        """Initialize the certificate manager with DNS and secrets plugins.

        Loads Let’s Encrypt configuration from settings and stores the provided DNS
        and secrets plugin instances for use throughout the ACME workflow.

        Args:
            dns_plugin (DNSBase): DNS management plugin used to create, update, and
                verify challenge records.
            secrets_plugin (SecretsBase): Secrets management plugin used to retrieve
                the ACME account key and store certificate material (PEMs).

        Returns:
            None
        """
        self.le_directory_url = settings.LE_DIRECTORY_URL
        self.le_account_key_secret_name = settings.LE_ACCOUNT_KEY_SECRET_NAME
        self.le_account_key_secret = settings.LE_ACCOUNT_KEY_SECRET
        self.dns = dns_plugin
        self.secrets = secrets_plugin

    def request_cert(self, domain: str, zone_id: str):
        """Request and provision a certificate for a single domain via ACME (LE).

        Orchestrates the full certificate request flow:
        creates an ACME order, prepares DNS-01 challenges, updates DNS records,
        finalizes the order to obtain the full-chain certificate,
        stores certificate materials in the secrets backend,
        and, if applicable, restores any prior CNAME record.

        Args:
            domain (str): Fully qualified domain name to issue/renew a certificate for.
            zone_id (str): Route53 (or provider) hosted zone identifier for the domain.

        Returns:
            list[dict] | str: On success, a list of objects describing stored
                certificate materials (e.g., ARNs). On failure, a string error
                message (e.g., when DNS update fails or ACME finalization returns
                an error).

        Notes:
            - Updates DNS records for the ACME DNS-01 challenge and waits for
              propagation.
            - Stores the private key, CSR, and full chain in the secrets backend.
        """
        logger.info(f"Requesting certificate for {domain}")

        try:
            client_acme, order_object, pkey_pem, csr_pem = self._begin_acme_order(domain)
            dns_data = self._prepare_dns_challenges(client_acme, order_object)
            ready_to_validate = self._update_dns([i[2] for i in dns_data], domain, zone_id)

            if ready_to_validate is not True:
                return f"Error: DNS update failed for {domain}"

            fullchain_pem = self._finalize_acme_order(client_acme, order_object, dns_data, domain)
            if isinstance(fullchain_pem, str) and fullchain_pem.startswith("Error"):
                return fullchain_pem

            arns = self._store_cert_materials(domain, pkey_pem, csr_pem, fullchain_pem)
            return arns

        except Exception as e:
            err = f"Unexpected error requesting cert for {domain}: {e}"
            logger.exception(err)
            return err

    def _begin_acme_order(self, domain):
        """Initialize ACME client and begin a certificate order for a domain.

        Loads the Let’s Encrypt account key from the secrets backend, constructs the
        ACME client, registers (only if an existing account is found), creates a new
        private key and CSR for the domain, and opens a new order.

        Args:
            domain (str): Fully qualified domain name to include in the CSR (also
                used to generate a wildcard SAN `*.{domain}`).

        Returns:
            tuple[acme.client.ClientV2, Any, bytes, bytes] | bool:
                On success, a 4-tuple of:
                - client_acme: Initialized ACME v2 client.
                - order_object: The ACME order resource created for the CSR.
                - pkey_pem: PEM-encoded RSA private key (bytes).
                - csr_pem: PEM-encoded certificate signing request (bytes).
                Returns `False` if the stored account key is not valid JSON.

        Raises:
            Exception: May propagate exceptions from ACME/HTTP or cryptography
                libraries if network calls or cryptographic operations fail.
        """
        account_secret = self.secrets.get_secret_value(self.le_account_key_secret_name)
        try:
            account_key = json.loads(account_secret.strip())
        except json.decoder.JSONDecodeError:
            logger.exception(f"Lets Encrypt account key is not valid: {str(account_secret.strip())}")
            return False

        user_key = josepy.JWKRSA.fields_from_json(account_key)
        net = ClientNetwork(user_key)
        directory = messages.Directory.from_json(net.get(self.le_directory_url).json())
        client_acme = ClientV2(directory, net)
        reg = messages.NewRegistration(key=user_key.public_key(), only_return_existing=True)
        response = client_acme._post(directory['newAccount'], reg)
        regr = client_acme._regr_from_response(response)
        client_acme.query_registration(regr)

        # Create domain private key and CSR
        pkey_pem, csr_pem = self._new_csr(domain)
        order_object = client_acme.new_order(csr_pem)
        return client_acme, order_object, pkey_pem, csr_pem

    def _prepare_dns_challenges(self, client_acme, order_object):
        """Prepare ACME DNS-01 challenges for the current order.

        Fetches the DNS-01 challenge objects from the ACME order and converts each
        into a tuple of the challenge, its corresponding response object, and the
        validation token needed for DNS TXT records.

        Args:
            client_acme: The initialized ACME v2 client.
            order_object: The ACME order resource containing authorizations.

        Returns:
            list[list]: A list where each item is
                `[challenge_body, response_object, validation_token]` for a DNS-01
                challenge associated with the order.
        """
        logger.info("Requesting DNS challenges")
        dns_challenge_objects = self._get_dns_challenge(order_object)

        logger.info("Converting tokens")
        dns_data = []
        for obj in dns_challenge_objects:
            response, validation_token = obj.response_and_validation(client_acme.net.key)
            dns_data.append([obj, response, validation_token])
        return dns_data

    def _finalize_acme_order(self, client_acme, order_object, dns_data, domain):
        """Finalize an ACME order by answering DNS-01 challenges and polling for completion.

        Iterates through the prepared DNS-01 challenges, submits each answer to the
        ACME server, and then polls the order until it is finalized or the timeout
        is reached. On success, returns the full-chain certificate in PEM format.

        Args:
            client_acme: The initialized ACME v2 client used to answer challenges
                and finalize the order.
            order_object: The ACME order resource to be finalized.
            dns_data (list[list]): Challenge tuples produced by `_prepare_dns_challenges`,
                each in the form `[challenge_body, response_object, validation_token]`.
            domain (str): The fully qualified domain name associated with the order,
                used for logging and error messages.

        Returns:
            str: The PEM-encoded full-chain certificate on success, or a human-readable
                error string on failure.

        Notes:
            - Uses a fixed timeout of 180 seconds for `poll_and_finalize`.
            - ACME validation errors are logged with details; a generic error string
              is returned in those cases.
        """
        try:
            logger.info('--------- authorizing')
            for challb, response, _ in dns_data:
                logger.info(f"Trying answer challenge: {challb} {response}")
                challenge_resource = client_acme.answer_challenge(challb, response)
                logger.info(f"Resulting challenge resource: {challenge_resource}")
            timeout = datetime.datetime.now() + datetime.timedelta(seconds=180)
            logger.info("Attempting acme finalize order to validate auth")
            finalized_order = client_acme.poll_and_finalize(order_object, timeout)
            logger.info("LE Auth valid")
            return finalized_order.fullchain_pem
        except errors.ValidationError as e:
            logger.exception(f"Validation error on {domain}: {e.failed_authzrs}")
            return f"Error validating domain {domain}. See logs for details."
        except Exception as e:
            err = f"Error: Answer challenge exception for {domain}: {e}"
            logger.exception(err)
            return err

    def _store_cert_materials(self, domain, pkey_pem, csr_pem, fullchain_pem):
        """Persist certificate materials to the secrets backend.

        Packages the CSR, private key, and full-chain certificate into a list and
        delegates storage to `_store_pems`. Returns the resulting identifiers (e.g.,
        ARNs) on success or a string error message on failure.

        Args:
            domain (str): The fully qualified domain name the materials belong to.
            pkey_pem (bytes | str): PEM-encoded private key.
            csr_pem (bytes | str): PEM-encoded certificate signing request.
            fullchain_pem (bytes | str): PEM-encoded full-chain certificate.

        Returns:
            list[dict] | str: A list of stored item identifiers on success, or a
                string error message on failure.
        """
        pem_list = [
            {'key': 'csr', 'value': csr_pem},
            {'key': 'private_key', 'value': pkey_pem},
            {'key': 'fullchain', 'value': fullchain_pem}
        ]
        try:
            arns = self._store_pems(domain, pem_list)
            return arns
        except Exception as e:
            err = f"Error storing certificate for {domain}: {e}"
            logger.exception(err)
            return err

    def _new_csr(self, domain, pkey_pem=None):
        """Create a new CSR (and key if needed) for the given domain.

        Generates a new RSA private key when `pkey_pem` is not provided and builds a
        CSR that includes both the apex domain and a wildcard SAN (`*.{domain}`).

        Args:
            domain (str): The fully qualified domain name to include in the CSR and
                as the basis for the wildcard SAN.
            pkey_pem (bytes | None): Optional PEM-encoded private key. If `None`, a
                new 2048-bit RSA key is generated and returned.

        Returns:
            tuple[bytes, bytes]: A `(pkey_pem, csr_pem)` tuple containing the
                PEM-encoded private key and the PEM-encoded CSR.
        """
        if pkey_pem is None:
            pkey = crypto.PKey()
            pkey.generate_key(crypto.TYPE_RSA, 2048)
            pkey_pem = crypto.dump_privatekey(FILETYPE_PEM, pkey)
        csr_pem = crypto_util.make_csr(pkey_pem, [domain, "*."+domain])
        return pkey_pem, csr_pem

    def _get_dns_challenge(self, order_object):
        """Extract DNS-01 challenges from the ACME order authorizations.

        Iterates over the order’s authorizations and collects all DNS-01 challenge
        bodies offered by the CA. Logs an informational message when no DNS-01
        challenges are present.

        Args:
            order_object: The ACME order resource whose authorizations will be
                inspected for DNS-01 challenges.

        Returns:
            list: A list of challenge body objects for DNS-01; an empty list if none
                are offered.
        """
        # This object holds the offered challenges by server and status.
        authz_list = order_object.authorizations
        chall = []
        for authz in authz_list:
            for i in authz.body.challenges:
                if isinstance(i.chall, challenges.DNS01):
                    chall.append(i)
        if not chall:
            logger.info("DNS-01 challenge was not offered by the CA server.")
        return chall

    def _update_dns(self, tokens, domain, zone_id):
        """Update DNS records required for ACME DNS-01 validation.

        Clears any existing `_acme-challenge` TXT records for the domain,
        builds the TXT record in the domain’s hosted zone, and applies the changes.
        Returns `False` immediately if no validation tokens are provided.

        Args:
            tokens (list[str]): Validation token strings for the TXT record.
            domain (str): The fully qualified domain name being validated.
            zone_id (str): The hosted zone identifier for the domain.

        Returns:
            bool: `True` if DNS changes were submitted; `False` if no tokens were
                provided.

        Raises:
            Exception: Propagated from DNS change operations when an apply step
                fails (via `_apply_dns_change`).
        """
        logger.info(f"Starting DNS update for {domain} in zone {zone_id}")
        if not tokens:
            return False

        try:
            self.dns.clear_old_acme_txt(domain, zone_id)
        except Exception as e:
            err = f"Error clearing older acme challenge for {domain}: {e}"
            logger.exception(err)
            # This is just an informational error, no need to return anything here.

        account_record = self.dns.build_domain_validation_record(tokens, domain, zone_id)
        logger.info(f"Applying TXT record in zone for {domain}")
        self._apply_dns_change(account_record)

        logger.info(f"DNS update complete for {domain}")
        return True

    def _apply_dns_change(self, record):
        """Apply a single DNS change and surface failures.

        Delegates the record update to the DNS plugin and raises any exception
        encountered so the caller can handle or abort the flow.

        Args:
            record (dict): DNS record change payload containing an `RRSet` with
                `Name`, `Type`, `ResourceRecords`, and `TTL`.

        Raises:
            Exception: Propagates any error raised by the DNS plugin during the
                change operation.
        """
        try:
            self.dns.change_dns(record)
        except Exception as e:
            err = f"Error: DNS change failed for {record['RRSet']['Name']}: {e}"
            logger.exception(err)
            raise e

    def _store_pems(self, domain, pem_list):
        """Store the complete set of certificate materials for a domain.

        Iterates over the provided PEM items, stores each via the secrets plugin,
        and returns a list of identifiers for the created/updated secrets. A fixed
        set of resource tags is applied to each stored item.

        Args:
            domain (str): The fully qualified domain name the materials belong to.
            pem_list (list[dict]): Iterable of items to store, each dict containing:
                - 'key' (str): Logical name of the material (e.g., 'csr',
                  'private_key', 'fullchain').
                - 'value' (str | bytes): PEM-encoded content to store.

        Returns:
            list[dict]: A list of dictionaries of the form
                `{'key': <original key>, 'value': <stored identifier>}` for each
                successfully stored item. Items that do not return an identifier are
                omitted from the result.
        """
        tags = [
            {"Key":"Owner","Value":"Your Team Name"},
            {"Key":"Environment","Value":"Production"},
            {"Key":"Application","Value":"tlstool"},
            {"Key":"Service","Value":"LetsEncrypt"}
        ]

        arns = []
        for pem in pem_list:
            arn = self.secrets.store_pem_secret(domain, pem, tags)
            if arn:
                arns.append({'key': pem['key'], 'value': arn})
        return arns
