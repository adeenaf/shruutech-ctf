import os, sqlite3

DB_PATH=os.environ.get("DB_PATH", "shruutech_ctf.db")
schema = """
CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY,
    title TEXT,
    hint TEXT,
    path_shown BOOLEAN,
    flag TEXT,
    points INTEGER
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT,
    total_score INTEGER DEFAULT 0, 
    password_hash TEXT
);
CREATE TABLE IF NOT EXISTS sqlite_sequence(name,seq);
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    challenge_id INTEGER,
    flag TEXT,
    status TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(challenge_id) REFERENCES challenges(id)
);
CREATE INDEX IF NOT EXISTS idx_users_total_score ON users(total_score DESC);
"""
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True) if os.path.dirname(DB_PATH) else None
with sqlite3.connect(DB_PATH) as conn:
    conn.executescript(schema)
print(f"SQLite ready at {DB_PATH}")