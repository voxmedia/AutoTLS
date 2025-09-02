from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

class DNSBase(ABC):
    """
    Abstract base class for DNS management plugins.
    Implementations should be idempotent and raise DNSError on recoverable DNS failures.
    """

    class DNSError(Exception):
        """Raised for DNS-related failures."""
        pass

    @abstractmethod
    def get_dns_client(self) -> Any:
        """Return the underlying DNS API client/session used by the plugin."""
        pass

    @abstractmethod
    def find_acme_record(self, zone_id: str) -> Optional[Dict[str, Any]]:
        """Locate an existing `_acme-challenge` RRSet in the given hosted zone, if any."""
        pass

    @abstractmethod
    def change_dns(self, record: Dict[str, Any]) -> bool:
        """UPSERT the provided RRSet and wait for propagation; return True on success."""
        pass

    @abstractmethod
    def wait_for_dns_change_insync(self, change_id: str, record: Dict[str, Any]) -> None:
        """Block until the change reaches INSYNC (or raise DNSError on failure/timeout)."""
        pass

    @abstractmethod
    def verify_dns_change(self, record: Dict[str, Any]) -> None:
        """Verify the UPSERT took effect; raise DNSError if verification fails."""
        pass

    @abstractmethod
    def clear_old_acme_txt(self, domain: str, zone_id: str) -> bool:
        """Delete any stale `_acme-challenge` TXT records for the domain in zone; True on success."""
        pass

    @abstractmethod
    def build_domain_validation_record(self, tokens: List[str], domain: str, zone_id: str) -> Dict[str, Any]:
        """Build the TXT `_acme-challenge.<domain>` RRSet used to validate multiple tokens under the domain."""
        pass

