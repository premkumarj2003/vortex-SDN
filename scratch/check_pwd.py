import sys
sys.path.insert(0, '.')
import sqlite3
from backend.models.database import verify_password

conn = sqlite3.connect('data/vortex.db')
c = conn.cursor()
c.execute("SELECT username, password_hash, salt FROM users WHERE username='naveengkumbar123'")
row = c.fetchone()
if row:
    print('User found:', row[0])
    for cand in ['Password@123', 'Prem@2003', 'Naveen@123', 'Naveen@2024', 'Vortex@123', 'Naveen@1234', 'Naveen@123!', 'Naveen@2003', 'Password@1234']:
        if verify_password(cand, row[1], row[2]):
            print('PASSWORD IS:', cand)
            break
conn.close()
