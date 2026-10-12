"""neo4j connection settings, read from the repository's .env file."""
from pathlib import Path

from dotenv import load_dotenv
import os

from neo4j import GraphDatabase

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")  # variables already set, for example on vercel, take priority

# some python installs (the python.org macOS installer) ship without trusted certificate authorities,
# which breaks encrypted connections to neo4j aura. certifi provides the standard list.
try:
    import certifi
    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
except ImportError:
    pass


def driver():
    return GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.environ.get("NEO4J_USERNAME") or os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]),
        notifications_min_severity="OFF",
    )
