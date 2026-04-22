"""Example: bridge between Voyagetrends and The Voyage Vault.

The two stores communicate through a secure, authenticated bridge.
Only the owner (you) manages this — the interface stays secret.
"""

from lmstudio.campaign_api import CampaignAPI

api = CampaignAPI()

OWNER = "owner@private.internal"

# ── Register stores ───────────────────────────────────────────────────────────

api.create("voyagetrends", owner=OWNER,
           metadata={"site": "voyagetrends.com"})
api.create("voyage-vault", owner=OWNER,
           metadata={"site": "thevoyagevault.com"})

# ── Add media to each store ───────────────────────────────────────────────────

api.add_media("voyagetrends", "photo", "assets/vt_hero.jpg",
              caption="Latest travel trends")
api.add_media("voyagetrends", "video", "assets/vt_intro.mp4",
              caption="Welcome to Voyagetrends", metadata={"duration_s": 30})

api.add_media("voyage-vault", "photo", "assets/vv_deals.jpg",
              caption="Exclusive deals")
api.add_media("voyage-vault", "video", "assets/vv_promo.mp4",
              caption="The Voyage Vault savings", metadata={"duration_s": 45})

# ── Build the bridge between the two stores ───────────────────────────────────

bridge = api.bridge("voyagetrends", "voyage-vault")
print(f"Bridge created: {bridge}\n")

# ── Stores send signed messages to each other ─────────────────────────────────

bridge.send("voyagetrends", "Hey Vault! Let's cross-promote our summer deals.")
bridge.send("voyage-vault", "Great idea! We'll feature your trends page too.")
bridge.send("voyagetrends", "Deal. Sharing our hero photo with you now.")

# ── Read each store's inbox ───────────────────────────────────────────────────

print("Voyage Vault inbox:")
for msg in bridge.inbox("voyage-vault"):
    valid = bridge.verify_message(msg)
    print(f"  [{msg.sender} → {msg.recipient}] {msg.content!r}  ✓={valid}")

print("\nVoyagetrends inbox:")
for msg in bridge.inbox("voyagetrends"):
    valid = bridge.verify_message(msg)
    print(f"  [{msg.sender} → {msg.recipient}] {msg.content!r}  ✓={valid}")

# ── Share media through the bridge ────────────────────────────────────────────

shared = bridge.share_media("voyagetrends", "voyage-vault", asset_type="photo")
print(f"\nVoyagetrends → Voyage Vault shared {len(shared)} photo(s):")
for a in shared:
    print(f"  {a}")

print(f"\nVoyage Vault media now: "
      f"{len(api.list_media('voyage-vault', 'photo'))} photo(s), "
      f"{len(api.list_media('voyage-vault', 'video'))} video(s)")

# ── Grant public expansion for both stores ────────────────────────────────────

for name in api.list_names():
    token = api.request_publication(name)
    api.grant_publication(name, token)

print("\nPublic views (owner never exposed):")
for view in api.list_public():
    print(f"  {view}")
