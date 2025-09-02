# methods for calls to our internal domain db

from datetime import datetime, timedelta
import logging
import os
import ssl

from pyasn1.codec.der.decoder import decode as asn1_decoder
from pyasn1_modules.rfc2459 import SubjectAltName
from pyasn1.codec.native.encoder import encode as nat_encoder

from flask import Blueprint, current_app, g
import OpenSSL
from sqlalchemy import or_, update
from sqlalchemy.exc import SQLAlchemyError

from tlstool import settings
from tlstool.database import db
from tlstool.helpers import retry_db_transaction
from tlstool.models import Domain, Tls

bp = Blueprint('domains', __name__)
logger = logging.getLogger(__name__)

class DomainManager:
    def __init__(self):
        """Initialize the domain manager with renewal window settings.

        Loads the renewal window (in days) from application settings for use in
        domain selection and renewal logic.

        Args:
            None

        Returns:
            None
        """
        self.renewal_window_days = settings.RENEWAL_WINDOW_DAYS

    def search_domains(self):
        """Fetch a list of domains eligible for TLS processing.

        In test mode (`g.testmode`), returns a fixed set of test domain entries with
        a synthetic expiration date ~10 days in the future. Otherwise, performs two
        database queries (using a shared base filter) to assemble up to 10 domains:

        1) Domains whose certificates are **not** issued by Let's Encrypt (or issuer
           is NULL), ordered by `tls_exp_date` ascending, limited to 10.
        2) If fewer than 10 were found in (1), add domains with Let's Encrypt-issued
           certificates that expire within `self.renewal_window_days`, ordered by
           `tls_exp_date` ascending, limited to the remaining slots.

        The base filter excludes parked/expired domains (or NULL status), requires
        ownership and non-empty zone data, and omits names in a local exclusion
        list. The result is logged and returned as a list of dictionaries.

        Returns:
            list[dict]: Domain metadata dicts of the form:
                {
                    'domain': str,
                    'zone_id': str,      # currently mapped from model field
                    'tls_exp_date': Any, # datetime/date as stored on the model
                    'tls_issuer': str | None
                }
        """
        testmode = getattr(g, 'testmode', None)
        if testmode:
            test_date = (datetime.now() + timedelta(days=10)).strftime('%Y-%m-%d 00:00:00')
            domain_list = [
                {'domain': 'example.com', 'zone_id': 'zone-XYZ123', 'tls_exp_date': f'{test_date}', 'tls_issuer': ''}
            ]
            logger.info(f"Testing these {len(domain_list)} domains: {domain_list}")
            return domain_list

        domain_list = []

        # Use this list to hold any domains in your database that you want to exclude from the TLS process:
        exclusion_list = ['exampletwo.com', 'examplethree.com']

        with current_app.app_context():
            base_query = Domain.query.filter(
                or_(Domain.status.notin_(['Parked', 'Expired']), Domain.status.is_(None)),
                Domain.zone_id != '',
                Domain.owned.is_(True),
                ~Domain.name.in_(exclusion_list),
            ).order_by(Domain.tls_exp_date.asc())

            logger.info("Search for domains with certs not issued by LE")
            non_le = base_query.filter(or_(Domain.tls_issuer != 'Lets Encrypt', Domain.tls_issuer.is_(None))).limit(10).all()
            for t in non_le:
                domain_list.append({'domain': t.name, 'zone_id': t.zone_id, 'tls_exp_date': t.tls_exp_date, 'tls_issuer': t.tls_issuer})

            remaining = 10 - len(non_le)
            if remaining > 0:
                logger.info("All active certs issued by LE, within renewal range")
                cutoff = datetime.utcnow() + timedelta(days=self.renewal_window_days)
                le_renew = base_query.filter(
                    Domain.tls_issuer == 'Lets Encrypt',
                    Domain.tls_exp_date < cutoff
                ).limit(remaining).all()
                for t in le_renew:
                    domain_list.append({'domain': t.name, 'zone_id': t.zone_id, 'tls_exp_date': t.tls_exp_date, 'tls_issuer': t.tls_issuer})

        logger.info(f"Processing these {len(domain_list)} domains: {domain_list}")
        return domain_list

    def domain_meta(self, domain):
        """Return metadata for a single domain.

        Executes a database query to fetch the selected fields for the given domain
        and formats the result as a list for consistency with the bulk search API.
        The list will contain zero or one item depending on whether the domain is
        found.

        Args:
        domain (str): The fully qualified domain name to look up.

        Returns:
        list[dict]: A list containing at most one dictionary with keys:
        'domain', 'zone_id', 'tls_exp_date', and 'tls_issuer'.
        """
        domain_list = []

        with current_app.app_context():
            query = Domain.query.with_entities(
                Domain.name,
                Domain.zone_id,
                Domain.tls_exp_date,
                Domain.tls_issuer
            ).filter(
                Domain.name == domain
            )
            domains = query.all()
            for t in domains:
                domain_list.append({'domain': t.name, 'zone_id': t.zone_id, 'tls_exp_date': t.tls_exp_date, 'tls_issuer': t.tls_issuer})

        return domain_list

    def get_domain_tls_status(self, domain, tls_issuer):
        """Assess the TLS status of a domain by inspecting its live certificate.

        Fetches the current server certificate from the domain on port 443, parses
        its expiration and subject names, and classifies status as:
        - 'ok': certificate valid, domain present in SAN/CN, not expiring soon.
        - 'renew': certificate valid but expires within 15 days.
        - 'new': certificate missing domain in SAN/CN or non–Let's Encrypt issuer.
        - 'unavailable': no certificate could be retrieved (EOF).

        Args:
            domain (str): Fully qualified domain name to check (assumes HTTPS on 443).
            tls_issuer (str | None): Known issuer string from metadata; if not
                equal to 'Lets Encrypt', status is set to 'new'.

        Returns:
            str: One of {'ok', 'renew', 'new', 'unavailable'} indicating the action
                needed for this domain.

        Notes:
            - Uses a 15-day renewal window based on the parsed certificate
              expiration date.
            - Logs detailed information and exceptions for troubleshooting.
        """
        status = 'ok'
        timestamp = ''

        try:
            logger.info(f"Checking {domain} for current certificate")
            cert = ssl.get_server_certificate((domain, 443))

            # Load a certificate (X509) from the string `_buffer_` encoded with `_type_`:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

            # Get the timestamp at which the certificate stops being valid:
            bytes = x509.get_notAfter()
            timestamp = bytes.decode('utf-8')

            readable_timestamp = datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat()
            logger.info(f"Current certificate for {domain} expires on {readable_timestamp}")
            exp_obj = datetime.strptime(readable_timestamp, '%Y-%m-%d')

            subjects = self._get_cert_subjects(x509)
            if domain not in subjects:
                logger.info(f"{domain} not in subject list, generate new certificate")
                status = 'new'

            if tls_issuer != 'Lets Encrypt':
                status = 'new'

            expires_in = exp_obj-datetime.now()
            # if the certificate expires within 15 days, time to renew
            if expires_in.days < 15:
                status = 'renew'
        except ssl.SSLEOFError:
            logger.exception(f"No certificate available for {domain}")
            status = 'unavailable'
        except Exception as e:
            logger.exception(f"Error retrieving TLS info from {domain}: {e}")
            status = "new"

        return status

    def _get_cert_subjects(self, x509):
        """Retrieve subject names (SAN and CN) from an X.509 certificate.

        Scans certificate extensions to locate the `subjectAltName`, decodes any DNS
        names, and returns them as strings. Also appends the certificate’s common
        name (CN) to the list.

        Args:
            x509 (OpenSSL.crypto.X509): Parsed certificate object to inspect.

        Returns:
            list[str]: Domain names present on the certificate (all SAN dNSName
                entries plus the CN).
        """
        # Find where the alt names are on the extension list
        alt_name_index = None
        for i in range(x509.get_extension_count()):
            ext_name = x509.get_extension(i).get_short_name().decode('utf-8')
            if ext_name == 'subjectAltName':
                alt_name_index = i
                break

            if alt_name_index is None:
                logger.debug("No subjectAltName extension found.")
                return []

        raw_names = x509.get_extension(alt_name_index).get_data()
        logger.debug(f"# get_extension().get_data() - Replace with pyca/cryptography's X.509 APIs: index - {alt_name_index}, raw_names - {raw_names}")
        decoded_names, _ = asn1_decoder(raw_names, asn1Spec=SubjectAltName())
        utf_alt_names = nat_encoder(decoded_names)
        subject_alt_names = [ x['dNSName'].decode('utf-8') for x in utf_alt_names]

        # Top-level subject
        raw_subject = x509.get_subject()
        subject = raw_subject.get_components()[0][1].decode('utf_8')
        subject_alt_names.append(subject) 
        logger.info(f'Subject list: {subject_alt_names}')
        return subject_alt_names

    @retry_db_transaction(max_retries=3, min_sleep=1, max_sleep=3)
    def domain_update(self, cert_obj):
        """Update domain database records with certificate metadata.

        Parses the certificate object returned from the upstream provider, inserts a
        new `Tls` row, and updates the corresponding `Domain` row with the new TLS
        identifiers and timestamps in a single transactional operation.

        Args:
            cert_obj (dict): Certificate payload with the shape:
                {
                    "cert": {
                        "data": {
                            "id": str,  # provider certificate identifier
                            "attributes": {
                                "not_after": str,
                                "not_before": str,
                                "created_at": str
                            },
                            "relationships": {
                                "tls_domains": {
                                    "data": [{"id": str}]  # first item used; may be "*.example.com"
                                }
                            }
                        }
                    }
                }

        Returns:
            bool: `True` if the transaction commits and at least one domain row is
                updated; `False` if an error occurs.

        Notes:
            - Uses `current_app.app_context()` and a SQLAlchemy session transaction.
            - Inserts a new `Tls` record, then updates the `Domain` row matching the
              derived apex domain (wildcard prefix is stripped).
            - Decorated with `@retry_db_transaction` for automatic retries on failure.
        """
        ## 1. Parse the certificate object 
        host = cert_obj['cert']['data']['relationships']['tls_domains']['data'][0]['id']
        domain = host.lstrip('*.')
        fastly_id = cert_obj['cert']['data']['id']
        not_after = cert_obj['cert']['data']['attributes']['not_after']
        not_before = cert_obj['cert']['data']['attributes']['not_before']
        created_at = cert_obj['cert']['data']['attributes']['created_at']
        logger.info(f"Update the domain db to indicate TLS record created for {domain}")

        ## 2. transactional insert and update
        try:
            with current_app.app_context():
                with db.session.begin():
                    new_tls = Tls(
                        fastly_id=fastly_id,
                        not_after=not_after,
                        not_before=not_before,
                        created_at=created_at
                    )
                    db.session.add(new_tls)
                    db.session.flush()  # ensures new_tls.id is populated

                    # Update domain record
                    stmt = (
                        update(Domain)
                        .where(Domain.name == domain)
                        .values(
                            tls_id=new_tls.id,
                            tls_exp_date=not_after,
                            tls_issuer='Lets Encrypt',
                            last_updated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            last_updated_by='tlstool'
                        )
                    )

                    result = db.session.execute(stmt)
                    if result.rowcount == 0:
                        raise RuntimeError(f"No tls record updated for {domain}")

                logger.info(f"Domain record for {domain} updated with SSL info at {os.environ['DBHOST']}")
                return True

        except (SQLAlchemyError, RuntimeError) as e:
            logger.exception(f"Error updating database for {domain}: {e}")
            return False
