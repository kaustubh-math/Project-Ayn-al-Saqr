import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isolate tests from the demo database and JWT secret. Must happen before the
# gateway modules are imported by test modules.
_TMP = Path(tempfile.mkdtemp(prefix="ayn-al-saqr-tests-"))
os.environ["AYN_DB_PATH"] = str(_TMP / "test.db")
os.environ["AYN_JWT_SECRET"] = "ayn-al-saqr-test-secret-0123456789abcdef"
os.environ["AYN_TOKEN_TTL"] = "300"
