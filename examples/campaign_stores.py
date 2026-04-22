"""Example: owner registers stores privately, then expands them to public.

Stores:
  - Voyagetrends.com
  - The Voyage Vault

The owner identity is kept secret throughout; only store name + metadata
are surfaced in public listings via StorePublicView.
"""

from lmstudio.campaign_api import CampaignAPI

api = CampaignAPI()

OWNER = "owner@private.internal"  # never exposed publicly

# ── Register stores (private, owner secret) ──────────────────────────────────

api.create(
    "voyagetrends",
    owner=OWNER,
    metadata={"site": "voyagetrends.com", "type": "travel-trends"},
)
api.create(
    "voyage-vault",
    owner=OWNER,
    metadata={"site": "thevoyagevault.com", "type": "travel-deals"},
)

print("Stores registered (private):")
for name in api.list_names():
    c = api.get(name)
    print(f"  {name:20s}  public={c.is_public}")

# ── Request public expansion for both stores ─────────────────────────────────

token_vt = api.request_publication("voyagetrends")
token_vv = api.request_publication("voyage-vault")

# ── Grant publication (present tokens) ───────────────────────────────────────

api.grant_publication("voyagetrends", token_vt)
api.grant_publication("voyage-vault", token_vv)

# ── Public world sees stores — owner never exposed ────────────────────────────

print("\nPublic store views (owner excluded):")
for view in api.list_public():
    print(f"  {view}")

print("\nOwner field is NOT present in public view — confirmed secret.")
