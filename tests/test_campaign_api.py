"""Tests for the Campaign API module."""

import pytest
from lmstudio.campaign_api import (
    Campaign,
    CampaignAPI,
    MPCSecretManager,
    SecretShare,
    StorePublicView,
    generate_strong_secret,
    _CAMPAIGN_TOKEN_PREFIX,
    _PUBLICATION_TOKEN_PREFIX,
    _PRIME,
)


# ---------------------------------------------------------------------------
# generate_strong_secret
# ---------------------------------------------------------------------------


def test_strong_secret_has_prefix():
    secret = generate_strong_secret()
    assert secret.startswith(_CAMPAIGN_TOKEN_PREFIX)


def test_strong_secret_length():
    secret = generate_strong_secret(byte_length=32)
    # prefix + 64 hex chars (32 bytes * 2)
    assert len(secret) == len(_CAMPAIGN_TOKEN_PREFIX) + 64


def test_strong_secret_uniqueness():
    secrets = {generate_strong_secret() for _ in range(100)}
    assert len(secrets) == 100


# ---------------------------------------------------------------------------
# MPCSecretManager
# ---------------------------------------------------------------------------


class TestMPCSecretManager:
    def setup_method(self):
        self.mpc = MPCSecretManager()

    def test_reconstruct_from_threshold(self):
        secret = 123456789
        shares = self.mpc.split(secret, n_shares=5, threshold=3)
        # Any 3 shares should reconstruct the secret
        assert self.mpc.reconstruct(shares[:3]) == secret
        assert self.mpc.reconstruct(shares[1:4]) == secret
        assert self.mpc.reconstruct(shares[2:5]) == secret

    def test_reconstruct_all_shares(self):
        secret = 987654321
        shares = self.mpc.split(secret, n_shares=3, threshold=3)
        assert self.mpc.reconstruct(shares) == secret

    def test_reconstruct_minimum_threshold(self):
        secret = 42
        shares = self.mpc.split(secret, n_shares=2, threshold=2)
        assert self.mpc.reconstruct(shares) == secret

    def test_split_produces_n_shares(self):
        shares = self.mpc.split(100, n_shares=7, threshold=4)
        assert len(shares) == 7
        indices = [s.index for s in shares]
        assert indices == list(range(1, 8))

    def test_split_shares_are_frozen(self):
        shares = self.mpc.split(1, n_shares=2, threshold=2)
        with pytest.raises((AttributeError, TypeError)):
            shares[0].value = 0  # type: ignore[misc]

    def test_threshold_greater_than_shares_raises(self):
        with pytest.raises(ValueError, match="Threshold cannot exceed"):
            self.mpc.split(1, n_shares=2, threshold=3)

    def test_threshold_less_than_2_raises(self):
        with pytest.raises(ValueError, match="Threshold must be at least 2"):
            self.mpc.split(1, n_shares=3, threshold=1)

    def test_secret_out_of_range_raises(self):
        with pytest.raises(ValueError, match="Secret must be in"):
            self.mpc.split(-1, n_shares=3, threshold=2)

    def test_large_secret(self):
        secret = _PRIME - 1
        shares = self.mpc.split(secret, n_shares=4, threshold=2)
        assert self.mpc.reconstruct(shares[:2]) == secret


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------


class TestCampaign:
    def _make(self, name="test", secret="sk-cam-" + "a" * 64, owner="owner@test"):
        return Campaign(name=name, secret=secret, _owner=owner)

    def test_sign_returns_hex_string(self):
        c = self._make()
        sig = c.sign("payload")
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 hex digest

    def test_verify_valid_signature(self):
        c = self._make()
        payload = '{"model":"llama3"}'
        assert c.verify(payload, c.sign(payload))

    def test_verify_rejects_tampered_payload(self):
        c = self._make()
        sig = c.sign("original")
        assert not c.verify("tampered", sig)

    def test_verify_rejects_tampered_signature(self):
        c = self._make()
        sig = c.sign("payload")
        bad_sig = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        assert not c.verify("payload", bad_sig)

    def test_different_secrets_produce_different_signatures(self):
        c1 = self._make(secret="sk-cam-" + "a" * 64)
        c2 = self._make(secret="sk-cam-" + "b" * 64)
        assert c1.sign("payload") != c2.sign("payload")


# ---------------------------------------------------------------------------
# CampaignAPI
# ---------------------------------------------------------------------------


class TestCampaignAPI:
    def setup_method(self):
        self.api = CampaignAPI()

    _OWNER = "owner@private.internal"

    def _create(self, name: str, **kw):
        return self.api.create(name, owner=self._OWNER, **kw)

    def test_create_returns_campaign(self):
        c = self._create("my-campaign")
        assert isinstance(c, Campaign)
        assert c.name == "my-campaign"

    def test_create_secret_has_prefix(self):
        c = self._create("x")
        assert c.secret.startswith(_CAMPAIGN_TOKEN_PREFIX)

    def test_create_stores_owner_privately(self):
        c = self._create("owned")
        assert c._owner == self._OWNER

    def test_create_duplicate_raises(self):
        self._create("dup")
        with pytest.raises(ValueError, match="already exists"):
            self._create("dup")

    def test_get_existing(self):
        c = self._create("found")
        assert self.api.get("found") is c

    def test_get_missing_returns_none(self):
        assert self.api.get("ghost") is None

    def test_delete_removes_campaign(self):
        self._create("gone")
        self.api.delete("gone")
        assert self.api.get("gone") is None

    def test_delete_missing_is_silent(self):
        self.api.delete("never-existed")  # should not raise

    def test_list_names(self):
        self._create("alpha")
        self._create("beta")
        names = self.api.list_names()
        assert "alpha" in names
        assert "beta" in names

    def test_metadata_stored(self):
        c = self._create("meta", metadata={"budget": 1000})
        assert c.metadata["budget"] == 1000

    def test_split_and_reconstruct_secret(self):
        campaign = self._create("secure")
        shares = self.api.split_secret(campaign, n_shares=5, threshold=3)
        assert len(shares) == 5
        recovered = self.api.reconstruct_secret(shares[:3])
        assert isinstance(recovered, str)
        assert recovered.startswith(_CAMPAIGN_TOKEN_PREFIX)

    def test_split_and_reconstruct_full_roundtrip(self):
        campaign = self._create("roundtrip")
        original_int = CampaignAPI._secret_to_int(campaign.secret)
        shares = self.api.split_secret(campaign, n_shares=3, threshold=2)
        recovered = self.api.reconstruct_secret(shares[:2])
        recovered_int = CampaignAPI._secret_to_int(recovered)
        assert recovered_int == original_int

    def test_campaign_can_sign_after_creation(self):
        c = self._create("signer")
        payload = "test payload"
        assert c.verify(payload, c.sign(payload))

    # ------------------------------------------------------------------
    # Owner secrecy: public view never exposes owner or secret
    # ------------------------------------------------------------------

    def test_public_view_excludes_owner(self):
        self._create("store", metadata={"site": "example.com"})
        view = self.api.public_view("store")
        assert isinstance(view, StorePublicView)
        assert not hasattr(view, "_owner")
        assert self._OWNER not in repr(view)

    def test_public_view_excludes_secret(self):
        c = self._create("store2")
        view = self.api.public_view("store2")
        assert c.secret not in repr(view)

    def test_public_view_missing_returns_none(self):
        assert self.api.public_view("ghost") is None

    def test_list_public_returns_public_view_objects(self):
        self._create("s1")
        token = self.api.request_publication("s1")
        self.api.grant_publication("s1", token)
        views = self.api.list_public()
        assert len(views) == 1
        assert isinstance(views[0], StorePublicView)

    def test_list_public_owner_never_in_output(self):
        self._create("s2", metadata={"site": "s2.com"})
        token = self.api.request_publication("s2")
        self.api.grant_publication("s2", token)
        for view in self.api.list_public():
            assert self._OWNER not in str(view)
            assert self._OWNER not in repr(view)

    # ------------------------------------------------------------------
    # Visibility: private by default, public via permission token
    # ------------------------------------------------------------------

    def test_new_campaign_is_private(self):
        c = self._create("private-store")
        assert c.is_public is False

    def test_list_public_names_empty_initially(self):
        self._create("a")
        self._create("b")
        assert self.api.list_public_names() == []

    def test_request_publication_returns_prefixed_token(self):
        self._create("store")
        token = self.api.request_publication("store")
        assert token.startswith(_PUBLICATION_TOKEN_PREFIX)

    def test_grant_publication_makes_campaign_public(self):
        c = self._create("store")
        token = self.api.request_publication("store")
        self.api.grant_publication("store", token)
        assert c.is_public is True

    def test_grant_publication_appears_in_public_list(self):
        self._create("public-store")
        self._create("private-store")
        token = self.api.request_publication("public-store")
        self.api.grant_publication("public-store", token)
        public = self.api.list_public_names()
        assert "public-store" in public
        assert "private-store" not in public

    def test_grant_publication_token_is_single_use(self):
        self._create("once")
        token = self.api.request_publication("once")
        self.api.grant_publication("once", token)
        with pytest.raises(PermissionError):
            self.api.grant_publication("once", token)

    def test_grant_publication_wrong_token_raises(self):
        self._create("wrong")
        self.api.request_publication("wrong")
        with pytest.raises(PermissionError):
            self.api.grant_publication("wrong", "bad-token")

    def test_grant_publication_without_request_raises(self):
        self._create("no-request")
        with pytest.raises(PermissionError):
            self.api.grant_publication("no-request", "any-token")

    def test_request_publication_unknown_campaign_raises(self):
        with pytest.raises(KeyError):
            self.api.request_publication("ghost")

    def test_grant_publication_unknown_campaign_raises(self):
        with pytest.raises(KeyError):
            self.api.grant_publication("ghost", "tok")

    def test_revoke_publication_makes_private(self):
        c = self._create("reversible")
        token = self.api.request_publication("reversible")
        self.api.grant_publication("reversible", token)
        assert c.is_public is True
        self.api.revoke_publication("reversible")
        assert c.is_public is False

    def test_revoke_publication_unknown_campaign_raises(self):
        with pytest.raises(KeyError):
            self.api.revoke_publication("ghost")

    def test_delete_removes_pending_token(self):
        self._create("temp")
        token = self.api.request_publication("temp")
        self.api.delete("temp")
        # Recreate with the same name; old token must not work
        self._create("temp")
        self.api.request_publication("temp")  # issue a new token
        with pytest.raises(PermissionError):
            self.api.grant_publication("temp", token)  # old token rejected

    def test_new_token_replaces_pending_token(self):
        self._create("replace")
        old_token = self.api.request_publication("replace")
        new_token = self.api.request_publication("replace")
        assert old_token != new_token
        with pytest.raises(PermissionError):
            self.api.grant_publication("replace", old_token)
        self.api.grant_publication("replace", new_token)  # new token works
