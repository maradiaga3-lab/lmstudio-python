"""Tests for the Campaign API module."""

import pytest
from lmstudio.campaign_api import (
    Campaign,
    CampaignAPI,
    MPCSecretManager,
    SecretShare,
    generate_strong_secret,
    _CAMPAIGN_TOKEN_PREFIX,
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
    def _make(self, name="test", secret="sk-cam-" + "a" * 64):
        return Campaign(name=name, secret=secret)

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

    def test_create_returns_campaign(self):
        c = self.api.create("my-campaign")
        assert isinstance(c, Campaign)
        assert c.name == "my-campaign"

    def test_create_secret_has_prefix(self):
        c = self.api.create("x")
        assert c.secret.startswith(_CAMPAIGN_TOKEN_PREFIX)

    def test_create_duplicate_raises(self):
        self.api.create("dup")
        with pytest.raises(ValueError, match="already exists"):
            self.api.create("dup")

    def test_get_existing(self):
        c = self.api.create("found")
        assert self.api.get("found") is c

    def test_get_missing_returns_none(self):
        assert self.api.get("ghost") is None

    def test_delete_removes_campaign(self):
        self.api.create("gone")
        self.api.delete("gone")
        assert self.api.get("gone") is None

    def test_delete_missing_is_silent(self):
        self.api.delete("never-existed")  # should not raise

    def test_list_names(self):
        self.api.create("alpha")
        self.api.create("beta")
        names = self.api.list_names()
        assert "alpha" in names
        assert "beta" in names

    def test_metadata_stored(self):
        c = self.api.create("meta", metadata={"budget": 1000})
        assert c.metadata["budget"] == 1000

    def test_split_and_reconstruct_secret(self):
        campaign = self.api.create("secure")
        shares = self.api.split_secret(campaign, n_shares=5, threshold=3)
        assert len(shares) == 5
        recovered = self.api.reconstruct_secret(shares[:3])
        # Reconstructed secret should round-trip through int conversion
        # and produce the same value when split again
        assert isinstance(recovered, str)
        assert recovered.startswith(_CAMPAIGN_TOKEN_PREFIX)

    def test_split_and_reconstruct_full_roundtrip(self):
        campaign = self.api.create("roundtrip")
        original_int = CampaignAPI._secret_to_int(campaign.secret)
        shares = self.api.split_secret(campaign, n_shares=3, threshold=2)
        recovered = self.api.reconstruct_secret(shares[:2])
        recovered_int = CampaignAPI._secret_to_int(recovered)
        assert recovered_int == original_int

    def test_campaign_can_sign_after_creation(self):
        c = self.api.create("signer")
        payload = "test payload"
        assert c.verify(payload, c.sign(payload))
