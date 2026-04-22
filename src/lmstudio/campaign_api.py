"""Campaign API with MPC-based secret sharing and strong secret generation.

.. note::
    This module is **intentionally not exported** from the top-level
    ``lmstudio`` package.  It is an internal interface whose symbols must
    be imported explicitly::

        from lmstudio.campaign_api import CampaignAPI

Visibility model
----------------
* Stores (campaigns) start **private** and can be expanded to **public**
  via a permission-token workflow.
* The **owner** identity is always kept **secret**: it is stored internally
  but never included in public-facing views or listings.
* :meth:`CampaignAPI.public_view` returns a :class:`StorePublicView` that
  exposes only the store name and public metadata — no secrets, no owner.
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Sequence


# Mersenne prime suitable for Shamir's Secret Sharing over GF(p)
_PRIME = 2**521 - 1

# Token prefix matching LM Studio token conventions
_CAMPAIGN_TOKEN_PREFIX = "sk-cam-"

# Prefix for one-time publication-permission tokens
_PUBLICATION_TOKEN_PREFIX = "pub-permit-"

# Allowed media asset types
MediaType = Literal["photo", "video"]


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


@dataclass
class MediaAsset:
    """A photo or video asset attached to a store campaign.

    Args:
        asset_type: ``"photo"`` or ``"video"``.
        url: Location of the asset (local path or remote URL).
        caption: Optional human-readable description.
        metadata: Arbitrary extra data (dimensions, duration, tags, …).
        uploaded_at: Unix timestamp when the asset was registered.
    """

    asset_type: MediaType
    url: str
    caption: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    uploaded_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.asset_type not in ("photo", "video"):
            raise ValueError(f"asset_type must be 'photo' or 'video', got {self.asset_type!r}")

    def __repr__(self) -> str:
        return (
            f"MediaAsset(type={self.asset_type!r}, url={self.url!r}, "
            f"caption={self.caption!r})"
        )


@dataclass(frozen=True)
class StorePublicView:
    """Public-safe snapshot of a campaign/store.

    Contains only what the world may see: name, public metadata, and media.
    Owner identity and API secret are **never** included.
    """

    name: str
    metadata: dict[str, Any]
    photos: list[MediaAsset]
    videos: list[MediaAsset]

    def __repr__(self) -> str:
        return (
            f"StorePublicView(name={self.name!r}, "
            f"photos={len(self.photos)}, videos={len(self.videos)})"
        )


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
    """A named campaign/store with a strong API secret and a private owner.

    * ``owner`` — always secret; never surfaced in public views.
    * ``secret`` — API secret for request signing; never surfaced publicly.
    * ``is_public`` — controls whether the store appears in public listings.

    Use :meth:`CampaignAPI.public_view` to obtain a safe, owner-free snapshot.
    """

    name: str
    secret: str
    # Owner is stored privately; CampaignAPI never exposes it in public output
    _owner: str = field(repr=False)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    is_public: bool = False
    media: list[MediaAsset] = field(default_factory=list)

    def sign(self, payload: str) -> str:
        """Return an HMAC-SHA256 hex signature for ``payload``."""
        return hmac.new(self.secret.encode(), payload.encode(), hashlib.sha256).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        """Return True iff ``signature`` matches the HMAC of ``payload``."""
        return hmac.compare_digest(self.sign(payload), signature)


class CampaignAPI:
    """Manages stores (campaigns) with public expansion and secret owner identity.

    **Owner stays secret** — owner info is held internally and never included
    in public listings or :class:`StorePublicView` snapshots.

    **Store visibility workflow**:

    1. :meth:`create` registers a store as private (``is_public=False``).
    2. :meth:`request_publication` issues a single-use permission token.
    3. :meth:`grant_publication` validates the token → store becomes public.
    4. :meth:`list_public` returns :class:`StorePublicView` objects (no secrets).

    Example::

        api = CampaignAPI()

        # Owner registers stores privately
        api.create("voyagetrends", owner="me@example.com",
                   metadata={"site": "voyagetrends.com"})
        api.create("voyage-vault", owner="me@example.com",
                   metadata={"site": "thevoyagevault.com"})

        # Request public expansion for each store
        token_vt = api.request_publication("voyagetrends")
        token_vv = api.request_publication("voyage-vault")

        # Grant publication (present tokens)
        api.grant_publication("voyagetrends", token_vt)
        api.grant_publication("voyage-vault", token_vv)

        # Public world sees stores — owner never exposed
        for view in api.list_public():
            print(view)   # StorePublicView(name=..., metadata={...})
    """

    def __init__(self) -> None:
        self._campaigns: dict[str, Campaign] = {}
        self._mpc = MPCSecretManager()
        # Pending one-time publication tokens: campaign name → token
        self._pending_publication_tokens: dict[str, str] = {}
        # Active bridges: frozenset({name_a, name_b}) → StoreBridge
        self._bridges: dict[frozenset[str], "StoreBridge"] = {}

    # ------------------------------------------------------------------
    # Campaign lifecycle
    # ------------------------------------------------------------------

    def create(
        self,
        name: str,
        *,
        owner: str,
        metadata: dict[str, Any] | None = None,
        secret_bytes: int = 32,
    ) -> Campaign:
        """Register a new **private** store with a secret owner identity.

        Args:
            name: Unique store identifier.
            owner: Owner identifier — kept secret, never exposed publicly.
            metadata: Public key/value pairs (site URL, category, etc.).
            secret_bytes: Entropy for the generated API secret (default 32).

        Returns:
            The newly created :class:`Campaign` (``is_public=False``).
        """
        if name in self._campaigns:
            raise ValueError(f"Campaign {name!r} already exists.")
        campaign = Campaign(
            name=name,
            secret=generate_strong_secret(secret_bytes),
            _owner=owner,
            metadata=metadata or {},
        )
        self._campaigns[name] = campaign
        return campaign

    def get(self, name: str) -> Campaign | None:
        """Return the full campaign record (owner visible), or ``None``."""
        return self._campaigns.get(name)

    def delete(self, name: str) -> None:
        """Remove the store and any pending publication token."""
        self._campaigns.pop(name, None)
        self._pending_publication_tokens.pop(name, None)

    def list_names(self) -> list[str]:
        """Return names of all stores (public and private)."""
        return list(self._campaigns)

    # ------------------------------------------------------------------
    # Public-facing views — owner and secret are never included
    # ------------------------------------------------------------------

    def public_view(self, name: str) -> StorePublicView | None:
        """Return a public-safe view of a store, or ``None`` if not found."""
        c = self._campaigns.get(name)
        if c is None:
            return None
        return self._make_public_view(c)

    def list_public(self) -> list[StorePublicView]:
        """Return public-safe views of all publicly visible stores.

        Owner identity and API secret are **never** included.
        Media assets (photos and videos) are included in the view.
        """
        return [self._make_public_view(c) for c in self._campaigns.values() if c.is_public]

    def list_public_names(self) -> list[str]:
        """Return names of publicly visible stores."""
        return [name for name, c in self._campaigns.items() if c.is_public]

    @staticmethod
    def _make_public_view(c: "Campaign") -> StorePublicView:
        photos = [a for a in c.media if a.asset_type == "photo"]
        videos = [a for a in c.media if a.asset_type == "video"]
        return StorePublicView(
            name=c.name,
            metadata=dict(c.metadata),
            photos=list(photos),
            videos=list(videos),
        )

    # ------------------------------------------------------------------
    # Media management
    # ------------------------------------------------------------------

    def add_media(
        self,
        name: str,
        asset_type: MediaType,
        url: str,
        *,
        caption: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> MediaAsset:
        """Attach a photo or video asset to store ``name``.

        Args:
            name: Store identifier.
            asset_type: ``"photo"`` or ``"video"``.
            url: File path or remote URL of the asset.
            caption: Optional description shown publicly.
            metadata: Extra data (dimensions, duration, tags, …).

        Returns:
            The newly created :class:`MediaAsset`.

        Raises:
            KeyError: If no store with ``name`` exists.
        """
        if name not in self._campaigns:
            raise KeyError(f"Campaign {name!r} not found.")
        asset = MediaAsset(
            asset_type=asset_type,
            url=url,
            caption=caption,
            metadata=metadata or {},
        )
        self._campaigns[name].media.append(asset)
        return asset

    def list_media(
        self,
        name: str,
        asset_type: MediaType | None = None,
    ) -> list[MediaAsset]:
        """Return media assets for store ``name``, optionally filtered by type.

        Raises:
            KeyError: If no store with ``name`` exists.
        """
        if name not in self._campaigns:
            raise KeyError(f"Campaign {name!r} not found.")
        assets = self._campaigns[name].media
        if asset_type is not None:
            return [a for a in assets if a.asset_type == asset_type]
        return list(assets)

    def remove_media(self, name: str, url: str) -> bool:
        """Remove the media asset with ``url`` from store ``name``.

        Returns:
            ``True`` if an asset was removed, ``False`` if not found.

        Raises:
            KeyError: If no store with ``name`` exists.
        """
        if name not in self._campaigns:
            raise KeyError(f"Campaign {name!r} not found.")
        media = self._campaigns[name].media
        before = len(media)
        self._campaigns[name].media = [a for a in media if a.url != url]
        return len(self._campaigns[name].media) < before

    # ------------------------------------------------------------------
    # Publication permission workflow
    # ------------------------------------------------------------------

    def request_publication(self, name: str) -> str:
        """Issue a single-use token to expand store ``name`` to public.

        Raises:
            KeyError: If no store with ``name`` exists.
        """
        if name not in self._campaigns:
            raise KeyError(f"Campaign {name!r} not found.")
        token = f"{_PUBLICATION_TOKEN_PREFIX}{secrets.token_hex(24)}"
        self._pending_publication_tokens[name] = token
        return token

    def grant_publication(self, name: str, token: str) -> None:
        """Make store ``name`` publicly visible by presenting a valid token.

        Token is consumed on success (single-use).

        Raises:
            KeyError: If no store with ``name`` exists.
            PermissionError: If ``token`` is invalid or already used.
        """
        if name not in self._campaigns:
            raise KeyError(f"Campaign {name!r} not found.")
        expected = self._pending_publication_tokens.get(name)
        if expected is None or not hmac.compare_digest(expected, token):
            raise PermissionError(
                f"Invalid or expired publication token for campaign {name!r}."
            )
        del self._pending_publication_tokens[name]
        self._campaigns[name].is_public = True

    def revoke_publication(self, name: str) -> None:
        """Revert a public store back to private.

        Raises:
            KeyError: If no store with ``name`` exists.
        """
        if name not in self._campaigns:
            raise KeyError(f"Campaign {name!r} not found.")
        self._campaigns[name].is_public = False

    # ------------------------------------------------------------------
    # MPC secret distribution
    # ------------------------------------------------------------------

    def split_secret(
        self, campaign: Campaign, *, n_shares: int, threshold: int
    ) -> list[SecretShare]:
        """Split ``campaign``'s secret into ``n_shares`` MPC shares."""
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
        raw = secret.removeprefix(_CAMPAIGN_TOKEN_PREFIX)
        value = (
            int(raw, 16)
            if all(c in "0123456789abcdef" for c in raw)
            else int.from_bytes(raw.encode(), "big")
        )
        if value >= _PRIME:
            value %= _PRIME
        return value

    @staticmethod
    def _int_to_secret(value: int) -> str:
        return f"{_CAMPAIGN_TOKEN_PREFIX}{format(value, '064x')}"

    # ------------------------------------------------------------------
    # Store bridge
    # ------------------------------------------------------------------

    def bridge(self, name_a: str, name_b: str) -> "StoreBridge":
        """Return (creating if needed) the bidirectional bridge between two stores.

        The bridge lets the two stores send authenticated messages to each
        other and share media assets.

        Raises:
            KeyError: If either store does not exist.
            ValueError: If ``name_a == name_b``.
        """
        if name_a == name_b:
            raise ValueError("A store cannot bridge to itself.")
        for name in (name_a, name_b):
            if name not in self._campaigns:
                raise KeyError(f"Campaign {name!r} not found.")
        key: frozenset[str] = frozenset({name_a, name_b})
        if key not in self._bridges:
            self._bridges[key] = StoreBridge(
                self._campaigns[name_a],
                self._campaigns[name_b],
            )
        return self._bridges[key]


# ---------------------------------------------------------------------------
# StoreBridge — bidirectional authenticated channel between two stores
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BridgeMessage:
    """A signed message sent from one store to another through a bridge."""

    sender: str
    recipient: str
    content: str
    signature: str   # HMAC-SHA256 of ``content`` signed with sender's secret
    sent_at: float = field(default_factory=time.time)

    def __repr__(self) -> str:
        preview = self.content[:40] + ("…" if len(self.content) > 40 else "")
        return (
            f"BridgeMessage(from={self.sender!r}, to={self.recipient!r}, "
            f"content={preview!r})"
        )


class StoreBridge:
    """Bidirectional authenticated communication channel between two stores.

    Messages are signed with the sender's campaign secret and verified by
    the recipient before delivery.  Media assets can also be pushed from
    one store to the other through the bridge.

    Obtain an instance via :meth:`CampaignAPI.bridge`.

    Example::

        bridge = api.bridge("voyagetrends", "voyage-vault")

        # Send a signed message from voyagetrends to voyage-vault
        bridge.send("voyagetrends", "Hey, let's cross-promote our deals!")

        # voyage-vault reads its inbox
        for msg in bridge.inbox("voyage-vault"):
            print(msg)

        # Share a photo from voyage-vault to voyagetrends
        bridge.share_media("voyage-vault", "voyagetrends", asset_type="photo")
    """

    def __init__(self, store_a: Campaign, store_b: Campaign) -> None:
        self._stores: dict[str, Campaign] = {
            store_a.name: store_a,
            store_b.name: store_b,
        }
        self._messages: list[BridgeMessage] = []

    @property
    def store_names(self) -> tuple[str, str]:
        """Names of the two connected stores."""
        names = list(self._stores)
        return names[0], names[1]

    def _peer(self, sender_name: str) -> Campaign:
        """Return the *other* store given one side's name."""
        names = list(self._stores)
        return self._stores[names[1] if sender_name == names[0] else names[0]]

    def send(self, sender_name: str, content: str) -> BridgeMessage:
        """Send a signed message from ``sender_name`` to the other store.

        The message is signed with the sender's campaign secret and verified
        before being queued in the recipient's inbox.

        Raises:
            KeyError: If ``sender_name`` is not one of the two bridged stores.
        """
        if sender_name not in self._stores:
            raise KeyError(f"{sender_name!r} is not part of this bridge.")
        sender = self._stores[sender_name]
        recipient = self._peer(sender_name)
        signature = sender.sign(content)
        msg = BridgeMessage(
            sender=sender_name,
            recipient=recipient.name,
            content=content,
            signature=signature,
            sent_at=time.time(),
        )
        # Verify before storing (guards against internal corruption)
        if not sender.verify(content, signature):
            raise ValueError("Message signature verification failed unexpectedly.")
        self._messages.append(msg)
        return msg

    def inbox(self, store_name: str) -> list[BridgeMessage]:
        """Return all messages addressed to ``store_name``, oldest first.

        Raises:
            KeyError: If ``store_name`` is not one of the two bridged stores.
        """
        if store_name not in self._stores:
            raise KeyError(f"{store_name!r} is not part of this bridge.")
        return [m for m in self._messages if m.recipient == store_name]

    def verify_message(self, msg: BridgeMessage) -> bool:
        """Return True if ``msg``'s signature is valid for its sender's secret."""
        sender = self._stores.get(msg.sender)
        if sender is None:
            return False
        return sender.verify(msg.content, msg.signature)

    def share_media(
        self,
        from_name: str,
        to_name: str,
        *,
        asset_type: "MediaType | None" = None,
    ) -> list[MediaAsset]:
        """Copy media assets from one store to the other through the bridge.

        Args:
            from_name: Store providing the assets.
            to_name: Store receiving the assets.
            asset_type: ``"photo"``, ``"video"``, or ``None`` for all.

        Returns:
            List of assets that were copied.

        Raises:
            KeyError: If either name is not part of this bridge.
        """
        for name in (from_name, to_name):
            if name not in self._stores:
                raise KeyError(f"{name!r} is not part of this bridge.")
        source = self._stores[from_name]
        target = self._stores[to_name]
        assets = (
            source.media
            if asset_type is None
            else [a for a in source.media if a.asset_type == asset_type]
        )
        existing_urls = {a.url for a in target.media}
        added: list[MediaAsset] = []
        for asset in assets:
            if asset.url not in existing_urls:
                target.media.append(asset)
                added.append(asset)
        return added

    def history(self) -> list[BridgeMessage]:
        """Return the full message history of this bridge, oldest first."""
        return list(self._messages)

    def __repr__(self) -> str:
        a, b = self.store_names
        return f"StoreBridge({a!r} ↔ {b!r}, messages={len(self._messages)})"
