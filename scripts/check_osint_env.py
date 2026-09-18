import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safenestt.local_env import load_local_osint_env
import os

load_local_osint_env()
keys = [
    "OPENROUTER_API_KEY", "ABUSEIPDB_API_KEY", "CENSYS_API_TOKEN", "DEHASHED_API_KEY",
    "FIRECRAWL_API_KEY", "HUNTER_API_KEY", "EMAIL_OSINT_API_KEY", "URLSCAN_API_KEY",
    "ETHERSCAN_API_KEY",
]
print({key: bool(os.getenv(key)) for key in keys})
