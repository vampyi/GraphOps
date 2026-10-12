"""neo4j connection settings, read from the repository's .env file."""
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase
import os

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")


def driver():
    return GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]),
        notifications_min_severity="OFF",
    )
