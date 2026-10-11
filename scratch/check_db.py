import sqlite3

conn = sqlite3.connect("data/vortex.db")
row = conn.execute("SELECT sql FROM sqlite_master WHERE name='operator_access_requests'").fetchone()
print("SQL:", row[0] if row else "None")
conn.close()
