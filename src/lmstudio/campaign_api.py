"""Campaign API with MPC-based secret sharing and strong secret generation."""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Sequence


# Mersenne prime suitable for Shamir's Secret Sharing over GF(p)
_PRIME = 2**521 - 1

# Token prefix matching LM Studio token conventions
_CAMPAIGN_TOKEN_PREFIX = "sk-cam-"


def generate_strong_secret(byte_length: int = 32) -> str:
    """Generate a cryptographically strong campaign API secret token."""
    raw = secrets.token_hex(byte_length)
    return f"{_CAMPAIGN_TOKEN_PREFIX}{raw}"


def _modinv(a: int, p: int) -> int:
    # Fermat's little theorem: a^(p-2) mod p gives a^(-1) mod p for prime p
    return pow(a, p - 2, p)


def _eval_poly(coeffs: list[int], x: int, p: int) -> int:
    return sum(c * pow(x, i, p) for i, c in enumerate(coeffs)) % p


@dataclass(frozen=True)
class SecretShare:
    """One participant's share produced by MPC secret splitting."""

    index: int
    value: int


class MPCSecretManager:
    """Shamir's Secret Sharing over a prime field for MPC-style secret distribution.

    Splits a secret integer into ``n`` shares so that any ``threshold``
    shares are sufficient to reconstruct it, but fewer reveal nothing.
    """

    def __init__(self, prime: int = _PRIME) -> None:
        self._prime = prime

    def split(self, secret: int, n_shares: int, threshold: int) -> list[SecretShare]:
        """Split ``secret`` into ``n_shares`` shares with the given ``threshold``."""
        if threshold < 2:
            raise ValueError("Threshold must be at least 2.")
        if threshold > n_shares:
            raise ValueError("Threshold cannot exceed the number of shares.")
        if secret < 0 or secret >= self._prime:
            raise ValueError("Secret must be in [0, prime).")
        p = self._prime
        # Random polynomial of degree (threshold-1) with secret as constant term
        coeffs = [secret] + [secrets.randbelow(p) for _ in range(threshold - 1)]
        return [SecretShare(i, _eval_poly(coeffs, i, p)) for i in range(1, n_shares + 1)]

    def reconstruct(self, shares: Sequence[SecretShare]) -> int:
        """Reconstruct the secret from ``shares`` via Lagrange interpolation."""
        p = self._prime
        xs = [s.index for s in shares]
        ys = [s.value for s in shares]
        secret = 0
        for i, (xi, yi) in enumerate(zip(xs, ys)):
            num = yi
            den = 1
            for j, xj in enumerate(xs):
                if i != j:
                    num = (num * (-xj % p)) % p
                    den = (den * ((xi - xj) % p)) % p
            secret = (secret + num * _modinv(den, p)) % p
        return secret


@dataclass
class Campaign:
    """A named campaign with a strong API secret for signing LLM interaction batches."""

    name: str
    secret: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def sign(self, payload: str) -> str:
        """Return an HMAC-SHA256 hex signature for ``payload``."""
        key = self.secret.encode()
        return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        """Return True iff ``signature`` matches the HMAC of ``payload``."""
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)


class CampaignAPI:
    """Manages LLM interaction campaigns with strong secrets and MPC distribution.

    Example usage::

        api = CampaignAPI()
        campaign = api.create("summer-promo", metadata={"budget": 5000})

        # Sign a request payload
        sig = campaign.sign('{"model": "llama3", "prompt": "Write ad copy"}')

        # Split the secret across 5 parties, reconstruct with any 3
        shares = api.split_secret(campaign, n_shares=5, threshold=3)
        recovered = api.reconstruct_secret(shares[:3])
        assert recovered == campaign.secret
    """

    def __init__(self) -> None:
        self._campaigns: dict[str, Campaign] = {}
        self._mpc = MPCSecretManager()

    # ------------------------------------------------------------------
    # Campaign lifecycle
    # ------------------------------------------------------------------

    def create(
        self,
        name: str,
        *,
        metadata: dict[str, Any] | None = None,
        secret_bytes: int = 32,
    ) -> Campaign:
        """Create a new campaign with a strong generated secret.

        Args:
            name: Unique campaign identifier.
            metadata: Arbitrary key/value pairs to attach to the campaign.
            secret_bytes: Entropy length for the generated secret (default 32 bytes).

        Returns:
            The newly created :class:`Campaign`.
        """
        if name in self._campaigns:
            raise ValueError(f"Campaign {name!r} already exists.")
        campaign = Campaign(
            name=name,
            secret=generate_strong_secret(secret_bytes),
            metadata=metadata or {},
        )
        self._campaigns[name] = campaign
        return campaign

    def get(self, name: str) -> Campaign | None:
        """Return the campaign with ``name``, or ``None`` if absent."""
        return self._campaigns.get(name)

    def delete(self, name: str) -> None:
        """Remove the campaign with ``name`` from the registry."""
        self._campaigns.pop(name, None)

    def list_names(self) -> list[str]:
        """Return the names of all registered campaigns."""
        return list(self._campaigns)

    # ------------------------------------------------------------------
    # MPC secret distribution
    # ------------------------------------------------------------------

    def split_secret(
        self, campaign: Campaign, *, n_shares: int, threshold: int
    ) -> list[SecretShare]:
        """Split ``campaign``'s secret into ``n_shares`` MPC shares.

        Any ``threshold`` shares can reconstruct the secret; fewer cannot.
        """
        secret_int = self._secret_to_int(campaign.secret)
        return self._mpc.split(secret_int, n_shares, threshold)

    def reconstruct_secret(self, shares: Sequence[SecretShare]) -> str:
        """Reconstruct and return the campaign secret from MPC ``shares``."""
        secret_int = self._mpc.reconstruct(shares)
        return self._int_to_secret(secret_int)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _secret_to_int(secret: str) -> int:
        """Convert a secret token string to an integer for MPC operations."""
        raw = secret.removeprefix(_CAMPAIGN_TOKEN_PREFIX)
        value = int(raw, 16) if all(c in "0123456789abcdef" for c in raw) else int.from_bytes(raw.encode(), "big")
        if value >= _PRIME:
            value %= _PRIME
        return value

    @staticmethod
    def _int_to_secret(value: int) -> str:
        """Convert a reconstructed integer back to a secret token string."""
        hex_str = format(value, "064x")
        return f"{_CAMPAIGN_TOKEN_PREFIX}{hex_str}"
