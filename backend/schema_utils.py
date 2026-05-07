import copy
import json
import logging
from pathlib import Path


LOGGER = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent
MASTER_SCHEMA_PATH = ROOT_DIR / "Master_Recon_Schema.json"

# Module-level cache — the schema file is read once and never re-read, which
# removes the per-call I/O overhead that affected deep/org scans with hundreds
# of recursive validation calls.
_MASTER_SCHEMA_CACHE: dict | None = None


def load_master_schema() -> dict:
    """Return the master schema, loading from disk only on first call."""
    global _MASTER_SCHEMA_CACHE
    if _MASTER_SCHEMA_CACHE is None:
        with MASTER_SCHEMA_PATH.open("r", encoding="utf-8") as handle:
            _MASTER_SCHEMA_CACHE = json.load(handle)
    return _MASTER_SCHEMA_CACHE


def clone_schema_section(path):
    section = load_master_schema()
    for key in path:
        section = section[key]
    return copy.deepcopy(section)


def create_scan_result(target):
    template = load_master_schema()
    template = copy.deepcopy(template)
    template["target"] = target
    template["subdomains"] = []
    template["hosts"] = []
    template["ai_analysis"] = {
        "summary": "",
        "risks": [],
        "recommendations": [],
    }
    return template


def validate_against_schema(data, schema=None, path="root"):
    """Validate *data* against *schema*.

    Policy:
      - Missing keys → ValueError (hard error — the pipeline always produces them)
      - Extra keys   → warning only (soft — downstream stages may attach extra
                        fields such as ``scan_id``, ``risk_score``, ``rag_analysis``,
                        ``pentest_plan`` that are not in the base schema)
    """
    if schema is None:
        schema = load_master_schema()

    if isinstance(schema, dict):
        if not isinstance(data, dict):
            raise ValueError(f"{path} must be an object")

        expected_keys = set(schema.keys())
        actual_keys = set(data.keys())

        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)

        if missing:
            raise ValueError(
                f"{path} does not match schema: missing keys: {missing}"
            )
        if extra:
            LOGGER.debug(
                "%s has extra keys (allowed, not validated): %s", path, extra
            )

        # Recurse only over known schema keys — extra keys are left untouched
        for key, value in schema.items():
            validate_against_schema(data[key], value, f"{path}.{key}")
        return

    if isinstance(schema, list):
        if not isinstance(data, list):
            raise ValueError(f"{path} must be a list")
        if schema:
            item_schema = schema[0]
            for index, item in enumerate(data):
                validate_against_schema(item, item_schema, f"{path}[{index}]")
        return

    if isinstance(schema, bool):
        if not isinstance(data, bool):
            raise ValueError(f"{path} must be a boolean")
        return

    if isinstance(schema, int) and not isinstance(schema, bool):
        if not isinstance(data, int):
            raise ValueError(f"{path} must be an integer")
        return

    if isinstance(schema, float):
        if not isinstance(data, (int, float)):
            raise ValueError(f"{path} must be a number")
        return

    if not isinstance(data, str):
        raise ValueError(f"{path} must be a string")
