import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("PHISHGUARD_DB", Path(__file__).resolve().parents[2] / "phishguard.db"))

def init_db() -> None:
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            input_type TEXT NOT NULL,
            input_label TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            probability REAL NOT NULL,
            result_json TEXT NOT NULL
        )""")
        connection.commit()

def save_analysis(result: dict[str, Any]) -> None:
    init_db()
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            "INSERT INTO analyses (timestamp, input_type, input_label, risk_level, probability, result_json) VALUES (?, ?, ?, ?, ?, ?)",
            (result["timestamp"], result["input_type"], result["input_label"], result["risk_level"], result["probability"], json.dumps(result)),
        )
        connection.commit()

def recent_analyses(limit: int = 25) -> list[dict[str, Any]]:
    init_db()
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT timestamp, input_type, input_label, risk_level, probability FROM analyses ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]
