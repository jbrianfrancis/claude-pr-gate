"""Tiny notes service used as the demo target for claude-pr-gate. Baseline (safe) version."""
import sqlite3
from contextlib import closing

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = "notes.db"


def db():
    return sqlite3.connect(DB)


def init_db():
    with closing(db()) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL)")
        conn.commit()


init_db()


@app.get("/notes/<int:note_id>")
def get_note(note_id: int):
    with closing(db()) as conn:
        row = conn.execute("SELECT id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(id=row[0], title=row[1], body=row[2])
