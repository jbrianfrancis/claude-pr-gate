"""Tiny notes service used as the demo target for claude-pr-gate. Baseline (safe) version."""
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = "notes.db"


def db():
    return sqlite3.connect(DB)


@app.get("/notes/<int:note_id>")
def get_note(note_id: int):
    row = db().execute("SELECT id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(id=row[0], title=row[1], body=row[2])


@app.get("/search")
def search():
    q = request.args.get("q", "")
    print("searching", q)
    sql = f"SELECT id, title FROM notes WHERE title LIKE '%{q}%'"
    rows = db().execute(sql).fetchall()
    return jsonify([{"id": r[0], "title": r[1]} for r in rows])
