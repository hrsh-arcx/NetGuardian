"""Tests for netguardian.inspection.signature_store"""

import pytest
from netguardian.inspection.signature_store import SignatureStore


@pytest.fixture
def store_with_sigs(tmp_path):
    """Create a store loaded from the project's signatures.yaml."""
    store = SignatureStore()
    # Use the actual project signatures file
    import os
    sig_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "signatures.yaml"
    )
    if os.path.exists(sig_path):
        store.load_from_file(sig_path)
    return store


class TestSignatureLoading:

    def test_loads_from_project_file(self, store_with_sigs):
        assert store_with_sigs.count >= 15  # we have 18 signatures

    def test_categories_indexed(self, store_with_sigs):
        cats = store_with_sigs.categories
        assert "sqli" in cats
        assert "xss" in cats

    def test_get_by_id(self, store_with_sigs):
        sig = store_with_sigs.get_by_id("NG-SQLI-001")
        assert sig is not None
        assert sig.category == "sqli"

    def test_get_by_category(self, store_with_sigs):
        sqli_sigs = store_with_sigs.get_by_category("sqli")
        assert len(sqli_sigs) >= 4

    def test_patterns_precompiled(self, store_with_sigs):
        for sig in store_with_sigs.get_all():
            assert sig.compiled is not None


class TestInvalidSignatures:

    def test_missing_field_skipped(self, tmp_path):
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text(
            "signatures:\n"
            "  - id: BAD-001\n"
            "    name: Missing fields\n"
        )
        store = SignatureStore()
        count = store.load_from_file(str(bad_yaml))
        assert count == 0

    def test_bad_regex_skipped(self, tmp_path):
        bad_yaml = tmp_path / "bad_regex.yaml"
        bad_yaml.write_text(
            "signatures:\n"
            "  - id: BAD-002\n"
            "    name: Bad regex\n"
            "    category: sqli\n"
            "    severity: high\n"
            "    action: block\n"
            "    target: uri\n"
            "    pattern: '(unclosed'\n"
        )
        store = SignatureStore()
        count = store.load_from_file(str(bad_yaml))
        assert count == 0

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        store = SignatureStore()
        count = store.load_from_file(str(empty))
        assert count == 0
