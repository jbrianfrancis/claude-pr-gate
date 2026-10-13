"""Tiny notes service used as the demo target for claude-pr-gate. Baseline (safe) version."""
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = "notes.db"


def db():
    """Open a connection with row access by column name."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/notes/<int:note_id>")
def get_note(note_id: int):
    row = db().execute("SELECT id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(id=row[0], title=row[1], body=row[2])
