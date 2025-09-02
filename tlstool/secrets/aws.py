import logging

import boto3
from botocore.exceptions import ClientError

from tlstool import settings
from tlstool.secrets import SecretsBase

logger = logging.getLogger(__name__)

class AWSSecretsManager(SecretsBase):
    """AWS Secrets Manager implementation of secrets plugin."""

    def __init__(self):
        """Initialize the AWS Secrets Manager plugin.

        Loads configuration from application settings (account key secret name,
        PEM secret base path, AWS credentials, and region) and constructs a
        provider client for subsequent secret operations.

        Args:
            None

        Returns:
            None
        """
        self.le_account_key_secret_name = settings.LE_ACCOUNT_KEY_SECRET_NAME
        self.pem_secret_base_path = settings.PEM_SECRET_BASE_PATH
        self.aws_access_key = settings.AWS_ACCESS_KEY
        self.aws_secret_key = settings.AWS_SECRET_KEY
        self.aws_region_name = getattr(settings, "AWS_REGION_NAME", "us-east-1")
        self.client = self.get_secrets_client()

    def get_secrets_client(self):
        """Return an authenticated boto3 Secrets Manager client.

        Initializes and returns a boto3 client for AWS Secrets Manager using the
        configured AWS access key, secret key, and region.

        Returns:
            botocore.client.SecretsManager: An authenticated client for Secrets
            Manager operations.

        Raises:
            SecretsBase.SecretsError: If the client cannot be created or
            authenticated.
        """
        try:
            logger.info(f"Creating SecretsManager client in region={self.aws_region_name!r}")
            client = boto3.client(
                'secretsmanager',
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                region_name=self.aws_region_name
            )
            return client
        except ClientError as error:
            logger.exception(error.response['Error']['Message']) 
            raise SecretsBase.SecretsError(error)

    def get_secret_value(self, secret_id: str):
        """Retrieve and return a secret string by identifier.

        Fetches the secret value from AWS Secrets Manager and returns its string
        content. On failure, logs and returns `False`.

        Args:
            secret_id (str): The Secrets Manager identifier (name or ARN).

        Returns:
            str | bool: The secret string on success; `False` on failure.
        """
        logger.info(f"Retrieving secret object: {secret_id}")
        try:
            response = self.client.get_secret_value(SecretId=secret_id)
            secret_str = response['SecretString']
            return secret_str
        except Exception as e:
            logger.exception(f"Error retrieving key {secret_id} from secrets manager: {e}")
            return False

    def store_pem_secret(self, domain, pem, tags):
        """Store or update a single PEM secret for a domain.

        Attempts to update the secret at the path `<base>/<domain>/<key>`. If the
        secret does not exist, delegates to `create_secret` to create it. Returns
        the secret ARN on success.

        Args:
            domain (str): Domain the PEM material belongs to.
            pem (dict): Dict with keys:
                - 'key' (str): Logical label (e.g., 'private_key', 'fullchain').
                - 'value' (str | bytes): PEM content to store.
            tags (list[dict]): Tag metadata to apply on creation.

        Returns:
            str: ARN of the stored or updated secret.
        """
        try:
            if isinstance(pem['value'], bytes):
                pem['value'] = pem['value'].decode("utf-8")
            response = self.client.update_secret(
                SecretId=f"{self.pem_secret_base_path}/{domain}/{pem['key']}",
                SecretString=pem['value']
            )
            logger.info(f"PEM stored: {response['Name']}")
            return response['ARN']
        except self.client.exceptions.ResourceNotFoundException:
            return self.create_secret(domain, pem, tags)

    def create_secret(self, domain, pem, tags):
        """Create a new secret for PEM material if it does not already exist.

        Creates a Secrets Manager entry at the path `<base>/<domain>/<key>` using
        the provided PEM content and tags. Returns the secret ARN on success, or
        `None` if creation fails (errors are logged).

        Args:
            domain (str): Domain the PEM material belongs to.
            pem (dict): Dict with keys:
                - 'key' (str): Logical label (e.g., 'private_key', 'fullchain').
                - 'value' (str): PEM content to store.
            tags (list[dict]): Tag metadata to apply to the secret.

        Returns:
            str | None: ARN of the newly created secret, or `None` on failure.
        """
        try:
            response = self.client.create_secret(
                Description=f"LE certificate signing request key for {domain}",
                Name=f"{self.pem_secret_base_path}/{domain}/{pem['key']}",
                SecretString=pem['value'],
                Tags=tags
            )
            logger.info(f"New secret created for {pem['key']}")
            return response['ARN']
        except Exception as e:
            logger.exception(f"Error creating secret for {pem['key']}: {e}")
            return None

