"""Example: registering stores as campaigns and requesting public visibility.

Stores managed here:
  - Voyagetrends.com
  - The Voyage Vault
"""

from lmstudio.campaign_api import CampaignAPI

api = CampaignAPI()

# ── Register stores (private by default) ────────────────────────────────────

voyagetrends = api.create(
    "voyagetrends",
    metadata={"site": "voyagetrends.com", "type": "travel-trends"},
)

voyage_vault = api.create(
    "voyage-vault",
    metadata={"site": "thevoyagevault.com", "type": "travel-deals"},
)

print("Stores registered (private):")
for name in api.list_names():
    c = api.get(name)
    print(f"  {name:20s}  public={c.is_public}")

# ── Request publication permission for both stores ───────────────────────────

token_voyagetrends = api.request_publication("voyagetrends")
token_voyage_vault = api.request_publication("voyage-vault")

print("\nPublication tokens issued:")
print(f"  voyagetrends : {token_voyagetrends}")
print(f"  voyage-vault : {token_voyage_vault}")

# ── Grant public visibility (present the tokens) ─────────────────────────────

api.grant_publication("voyagetrends", token_voyagetrends)
api.grant_publication("voyage-vault", token_voyage_vault)

print("\nPublic stores after permission granted:")
for name in api.list_public_names():
    c = api.get(name)
    print(f"  {name:20s}  public={c.is_public}  site={c.metadata.get('site')}")

# ── Show that the interface is still internal (not from top-level lmstudio) ──

print("\nInterface access check:")
print("  campaign_api is imported explicitly — not part of lmstudio public API.")
