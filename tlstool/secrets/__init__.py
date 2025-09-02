from abc import ABC, abstractmethod
from typing import Optional, Union

class SecretsBase(ABC):
    """Abstract base class for secrets management plugins."""

    class SecretsError(Exception):
        """Raised for DNS-related failures."""
        pass

    @abstractmethod
    def get_secrets_client(self) -> object:
        """Return an authenticated client for the secrets backend.

        Implementations should initialize and authenticate a provider-specific client
        (e.g., AWS Secrets Manager) using application settings/environment.

        Returns:
            object: An SDK client/handle ready for secret operations.

        Raises:
            SecretsError: If the client cannot be created or authenticated.
        """
        pass

    @abstractmethod
    def get_secret_value(self) -> Union[dict, bool]:
        """Retrieve and return a secret value from the backing store.

        Implementations should fetch the configured secret (e.g., an account key or
        PEM blob) and return a decoded structure on success.

        Returns:
            dict | bool: Parsed/decoded secret content on success; False on failure.

        Raises:
            SecretsError: If the secret cannot be retrieved or decoded.
        """
        pass

    @abstractmethod
    def store_pem_secret(self, domain: str, pem: str, tags: list[dict]) -> str:
        """Create or update a PEM secret for a domain and return its identifier.

        Implementations should upsert the secret at a deterministic path/key derived
        from the domain and PEM label, applying any provided resource tags.

        Args:
            domain (str): Domain the PEM material belongs to.
            pem (str): PEM content (or a structured object containing it).
            tags (list[dict]): Provider-specific tag metadata to apply.

        Returns:
            str: Provider identifier for the stored secret (e.g., ARN).

        Raises:
            SecretsError: If storage fails.
        """
        pass

    @abstractmethod
    def create_secret(self, domain: str, pem: str, tags: list[dict]) -> Optional[str]:
        """Create a new secret when it does not already exist.

        Implementations should create the secret with the provided content and tags
        and return the provider-specific identifier.

        Args:
            domain (str): Domain the PEM material belongs to.
            pem (str): PEM content (or a structured object containing it).
            tags (list[dict]): Provider-specific tag metadata to apply.

        Returns:
            str | None: Identifier for the newly created secret, or None on failure.

        Raises:
            SecretsError: If creation fails.
        """
        pass

