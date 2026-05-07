import sys
sys.path.insert(0, '/mnt/d/Download Manager/AIASDP/AIASDP')
sys.path.insert(0, '/mnt/d/Download Manager/AIASDP/AIASDP/venv/lib/python3.13/site-packages')

steps = [
    ("flask + flask_cors", "import flask, flask_cors"),
    ("config", "from backend.config import load_env; load_env()"),
    ("db_service", "from backend import db_service"),
    ("rag_ingest", "from backend import rag_ingest"),
    ("reasoning_chain", "from backend import reasoning_chain"),
    ("scan_service", "from backend.scan_service import perform_scan"),
    ("schema_utils", "from backend.schema_utils import create_scan_result"),
    ("full main import", "import main"),
]

for name, code in steps:
    try:
        exec(code)
        print(f"OK   {name}")
    except Exception as e:
        print(f"FAIL {name}: {e}")
    sys.stdout.flush()
