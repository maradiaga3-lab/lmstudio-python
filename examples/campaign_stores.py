"""Example: stores with photos and videos, owner stays secret.

Stores:
  - Voyagetrends.com
  - The Voyage Vault
"""

from lmstudio.campaign_api import CampaignAPI

api = CampaignAPI()

OWNER = "owner@private.internal"  # never exposed publicly

# ── Register stores ───────────────────────────────────────────────────────────

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

# ── Add photos and videos ─────────────────────────────────────────────────────

api.add_media("voyagetrends", "photo", "assets/vt_hero.jpg",
              caption="Explore the latest travel trends")
api.add_media("voyagetrends", "photo", "assets/vt_destinations.jpg",
              caption="Top destinations 2025")
api.add_media("voyagetrends", "video", "assets/vt_intro.mp4",
              caption="Welcome to Voyagetrends", metadata={"duration_s": 30})

api.add_media("voyage-vault", "photo", "assets/vv_deals.jpg",
              caption="Exclusive travel deals")
api.add_media("voyage-vault", "video", "assets/vv_promo.mp4",
              caption="The Voyage Vault – your secret to travel savings",
              metadata={"duration_s": 45})

print("Media uploaded (private):")
for store_name in api.list_names():
    photos = api.list_media(store_name, "photo")
    videos = api.list_media(store_name, "video")
    print(f"  {store_name}: {len(photos)} photo(s), {len(videos)} video(s)")

# ── Request and grant public expansion ───────────────────────────────────────

for store_name in api.list_names():
    token = api.request_publication(store_name)
    api.grant_publication(store_name, token)

# ── Public world sees stores + media — owner never exposed ───────────────────

print("\nPublic store views:")
for view in api.list_public():
    print(f"\n  {view}")
    for p in view.photos:
        print(f"    📷  {p.caption}  ({p.url})")
    for v in view.videos:
        dur = v.metadata.get("duration_s", "?")
        print(f"    🎬  {v.caption}  ({v.url}, {dur}s)")
