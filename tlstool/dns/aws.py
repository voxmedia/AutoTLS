import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from tlstool import settings
from tlstool.dns import DNSBase
from tlstool.helpers import jitter_sleep

logger = logging.getLogger(__name__)


class AWSRoute53(DNSBase):
    """AWS Route53 implementation of DNS plugin."""

    def __init__(self):
        """Initialize the AWS Route53 DNS plugin.

        Loads AWS credentials and the validation hosted zone ID from application
        settings, then constructs a Route53 client for subsequent DNS operations.

        Args:
            None

        Returns:
            None
        """
        self.aws_access_key = settings.AWS_ACCESS_KEY
        self.aws_secret_key = settings.AWS_SECRET_KEY 
        self.aws_region_name = getattr(settings, "AWS_REGION_NAME", "us-east-1")
        self.client = self.get_dns_client()

    def get_dns_client(self):
        """Return an authenticated boto3 Route 53 client.

        Initializes and returns a boto3 client for Amazon Route 53 using the
        configured AWS credentials.

        Returns:
            botocore.client.Route53: Authenticated client for Route 53 operations.

        Raises:
            DNSBase.DNSError: If the client cannot be created or authenticated.
        """
        try:
            logger.info(f"Creating Route53 client in region={self.aws_region_name!r}")
            client = boto3.client(
                'route53',
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                region_name=self.aws_region_name
            )
            return client
        except ClientError as error:
            logger.exception(error.response['Error']['Message'])
            raise DNSBase.DNSError(error)

    def find_acme_record(self, zone_id: str) -> Optional[Dict[str, Any]]:
        """Find an existing `_acme-challenge` record within a hosted zone.

        Iterates over the resource record sets for the specified hosted zone,
        handling pagination, and returns the first record set whose name starts
        with `_acme-challenge`.

        Args:
            zone_id (str): The Route 53 hosted zone identifier to search.

        Returns:
            dict | None: The matching resource record set dictionary if found;
                otherwise `None`.
        """
        found = False
        truncated = True
        params = {'HostedZoneId':zone_id}

        while not found and truncated:
            # list DNS records in the hosted zone
            lrrs = self.client.list_resource_record_sets(**params)
            if lrrs['IsTruncated']:
                truncated = True
                params.update({'StartRecordName': lrrs['NextRecordName']})
            else:
                truncated = False
            if len(lrrs['ResourceRecordSets']) > 0:
                for rrset in lrrs['ResourceRecordSets']:
                   if rrset['Name'].startswith('_acme-challenge') and rrset['Type'] == 'TXT':
                        found = True
                        return rrset
        return None

    def change_dns(self, record: Dict[str, Any]) -> bool:
        """UPSERT a DNS record in Route 53 and wait for propagation.

        Submits the change batch for the provided record, then waits until the
        change reaches `INSYNC` and verifies the resulting record.

        Args:
            record (dict): DNS change payload with keys:
                - 'ZoneID' (str): Hosted zone identifier.
                - 'RRSet' (dict): Route 53 `ResourceRecordSet` to UPSERT.

        Returns:
            bool: `True` once the change is submitted, propagated, and verified.

        Raises:
            DNSBase.DNSError: If the initial update request to Route 53 fails.
        """
        changeset = {'Changes': [{'Action': 'UPSERT', 'ResourceRecordSet': record['RRSet']}]} 
        try:
            response = self.client.change_resource_record_sets(
                HostedZoneId=record['ZoneID'],
                ChangeBatch=changeset
            )
            change_id = response['ChangeInfo']['Id']
            jitter_sleep(20, 30)
        except Exception as e:
            err = f"Error updating DNS: {e}"
            logger.exception(err)
            raise DNSBase.DNSError(err)

        self.wait_for_dns_change_insync(change_id, record)
        self.verify_dns_change(record)
        return True

    def wait_for_dns_change_insync(self, change_id: str, record: Dict[str, Any]) -> None:
        """Wait for a Route 53 DNS change to reach `INSYNC` status.

        Polls the change identified by `change_id` using `get_change` until its
        status becomes `INSYNC`, sleeping with jitter between checks. Logs progress
        using the record name and type for context.

        Args:
            change_id (str): The Route 53 change identifier returned by
                `change_resource_record_sets`.
            record (dict): DNS change payload containing `RRSet['Name']` and
                `RRSet['Type']`, used for logging.

        Returns:
            None
        """
        record_name = record['RRSet']['Name']
        record_type = record['RRSet']['Type']
        while True:
            jitter_sleep(20, 30)
            response = self.client.get_change(Id=change_id)
            status = response['ChangeInfo']['Status']
            logger.info(f"DNS UPSERT status for {record_name} {record_type}: {status}")
            if status == 'INSYNC':
                jitter_sleep(20, 30)
                break

    def verify_dns_change(self, record: Dict[str, Any]) -> None:
        """Verify that an UPSERTed DNS record is present and matches expectations.

        Lists resource record sets for the provided name and type in the target
        hosted zone, selects the first result, and compares its
        `ResourceRecords` to the expected values. Logs success on match; otherwise
        raises an exception.

        Args:
            record (dict): DNS change payload with:
                - 'ZoneID' (str): Hosted zone identifier.
                - 'RRSet' (dict): Expected Route 53 ResourceRecordSet containing
                  'Name', 'Type', and 'ResourceRecords'.

        Returns:
            None

        Raises:
            Exception: If the fetched record does not match the expected
                `ResourceRecords`.
        """
        record_name = record['RRSet']['Name']
        record_type = record['RRSet']['Type']
        logger.info(f"Verifying DNS change for {record_name} in {record['ZoneID']}")
        response = self.client.list_resource_record_sets(
            HostedZoneId=record['ZoneID'],
            StartRecordName=record_name,
            StartRecordType=record_type
        )

        actual = response['ResourceRecordSets'][0]
        if actual['ResourceRecords'] != record['RRSet']['ResourceRecords']:
            logger.error(f"DNS was not updated for {actual['Name']}")
            raise Exception("DNS update failed verification")
        else:
            logger.info("DNS update successful")

    def clear_old_acme_txt(self, domain: str, zone_id: str) -> bool:
        """Delete existing `_acme-challenge` TXT records for a domain and wait for propagation.

        Lists TXT records in the specified hosted zone for the domain’s
        `_acme-challenge` name, deletes any matches, and polls each deletion until
        the change reaches `INSYNC`.

        Args:
            domain (str): The fully qualified domain name whose ACME TXT records
                should be cleared.
            zone_id (str): The Route 53 hosted zone identifier to operate on.

        Returns:
            bool | str: `True` when all matching TXT records (if any) are deleted
                and INSYNC; otherwise an error message string if a delete request
                or status poll fails.
        """
        response = self.client.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordName=f'_acme-challenge.{domain}.',
            StartRecordType='TXT'
        )

        for x in response['ResourceRecordSets']:
            record_name = x['Name']
            record_type = x['Type']
            if record_name.startswith('_acme-challenge') and record_type == 'TXT':
                logger.info(f"Found TXT record to clear: {x}")
                changeset = {'Changes': [{'Action': 'DELETE', 'ResourceRecordSet': x}]}
                logger.info(f"Deleting {changeset}")
                try:
                    responsetwo = self.client.change_resource_record_sets(
                        HostedZoneId = zone_id,
                        ChangeBatch = changeset
                    )
                    try:
                        change_id = responsetwo['ChangeInfo']['Id']
                        while True:
                            jitter_sleep(20, 30)
                            responsethree = self.client.get_change(Id=change_id)
                            status = responsethree['ChangeInfo']['Status']
                            logger.info(f"Deletion status for {record_name}: {status}")
                            if status == 'INSYNC':
                                jitter_sleep(20, 30)
                                break
                    except Exception as e:
                        logger.exception(f"Error monitoring status on TXT deletion: {e}")
                except Exception as e:
                    err = f"Error removing acme-challenge TXT for {domain}: {e}"
                    logger.exception(err)
                    return err
        return True

    def build_domain_validation_record(self, tokens: List[str], domain: str, zone_id: str) -> Dict[str, Any]:
        """Build the TXT record for domain-specific DNS-01 validation.

        Constructs a Route 53 `ResourceRecordSet` for DNS-01 validation, using the
        configured validation hosted zone. Each token is wrapped in quotes for TXT
        record compliance.

        Args:
            tokens (list[str]): ACME validation tokens to publish as TXT values.
            domain (str): The fully qualified domain name being validated.
            zone_id (str): The hosted zone identifier where the CNAME will be created.

        Returns:
            dict: A change payload with keys:
                - 'ZoneID' (str): Validation hosted zone identifier.
                - 'RRSet' (dict): Record set containing:
                    - 'Name' (str): Validation record name derived from the domain.
                    - 'Type' (str): 'TXT'.
                    - 'ResourceRecords' (list[dict]): Quoted token values.
                    - 'TTL' (int): Time-to-live in seconds.

        """
        record = {
            'ZoneID': zone_id, 
            'RRSet': {
                'Name': f'_acme-challenge.{domain}.',
                'Type': 'TXT',
                'ResourceRecords': [{"Value": f'\"{t}\"'} for t in tokens],
                'TTL': 60
            }
        }   
        return record
