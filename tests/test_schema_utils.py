"""Tests for backend/schema_utils.py — schema caching, validation, and coercion."""

import pytest

from backend.schema_utils import (
    create_scan_result,
    load_master_schema,
    validate_against_schema,
)


# ---------------------------------------------------------------------------
# load_master_schema
# ---------------------------------------------------------------------------

class TestLoadMasterSchema:
    def test_returns_dict(self):
        schema = load_master_schema()
        assert isinstance(schema, dict)

    def test_contains_required_top_level_keys(self):
        schema = load_master_schema()
        for key in ("target", "hosts", "subdomains", "ai_analysis"):
            assert key in schema, f"Schema missing key: {key}"

    def test_caches_between_calls(self):
        """Repeated calls return the same object (module-level cache)."""
        s1 = load_master_schema()
        s2 = load_master_schema()
        assert s1 is s2


# ---------------------------------------------------------------------------
# create_scan_result
# ---------------------------------------------------------------------------

class TestCreateScanResult:
    def test_target_is_set(self):
        result = create_scan_result("example.com")
        assert result["target"] == "example.com"

    def test_hosts_is_empty_list(self):
        result = create_scan_result("example.com")
        assert result["hosts"] == []

    def test_subdomains_is_empty_list(self):
        result = create_scan_result("example.com")
        assert result["subdomains"] == []

    def test_ai_analysis_present(self):
        result = create_scan_result("example.com")
        assert "ai_analysis" in result
        assert isinstance(result["ai_analysis"]["risks"], list)

    def test_independent_copies(self):
        """Mutating one result must not affect another (deep copy)."""
        r1 = create_scan_result("a.com")
        r2 = create_scan_result("b.com")
        r1["hosts"].append({"hostname": "test"})
        assert r2["hosts"] == []


# ---------------------------------------------------------------------------
# validate_against_schema — happy paths
# ---------------------------------------------------------------------------

class TestValidateAgainstSchemaHappy:
    def test_minimal_valid_scan_passes(self, minimal_scan):
        # Should not raise
        validate_against_schema(minimal_scan)

    def test_extra_keys_do_not_raise(self, minimal_scan):
        """Extra top-level keys like scan_id must be allowed (soft validation)."""
        minimal_scan["scan_id"] = 42
        minimal_scan["risk_score"] = 55
        minimal_scan["rag_analysis"] = {}
        minimal_scan["pentest_plan"] = {}
        # Must not raise
        validate_against_schema(minimal_scan)

    def test_scan_with_host_passes(self, scan_with_host):
        validate_against_schema(scan_with_host)


# ---------------------------------------------------------------------------
# validate_against_schema — error paths
# ---------------------------------------------------------------------------

class TestValidateAgainstSchemaErrors:
    def test_missing_key_raises(self, minimal_scan):
        del minimal_scan["target"]
        with pytest.raises(ValueError, match="missing keys"):
            validate_against_schema(minimal_scan)

    def test_wrong_type_root_raises(self):
        with pytest.raises(ValueError, match="must be an object"):
            validate_against_schema("not a dict")

    def test_wrong_type_list_raises(self, minimal_scan):
        minimal_scan["hosts"] = "not a list"
        with pytest.raises(ValueError, match="must be a list"):
            validate_against_schema(minimal_scan)

    def test_schema_none_loads_master(self, minimal_scan):
        """Passing schema=None should auto-load the master schema."""
        validate_against_schema(minimal_scan, schema=None)


# ---------------------------------------------------------------------------
# validate_against_schema — primitive type checks
# ---------------------------------------------------------------------------

class TestValidatePrimitives:
    def test_string_schema_rejects_int(self):
        with pytest.raises(ValueError):
            validate_against_schema(42, schema="a string")

    def test_bool_schema_rejects_int(self):
        with pytest.raises(ValueError):
            validate_against_schema(1, schema=True)

    def test_int_schema_rejects_string(self):
        with pytest.raises(ValueError):
            validate_against_schema("3", schema=0)

    def test_float_schema_accepts_int(self):
        # Integers are valid floats
        validate_against_schema(3, schema=0.0)

    def test_list_schema_validates_items(self):
        validate_against_schema(["a", "b"], schema=[""])

    def test_list_schema_rejects_wrong_item_type(self):
        with pytest.raises(ValueError):
            validate_against_schema([1, 2], schema=[""])
