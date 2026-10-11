import sys, os
sys.path.insert(0, os.path.abspath('.'))
from backend.models.database import get_db_connection, hash_password
from backend.api.server import create_app
from backend.api.auth import ACTIVE_SESSIONS

app = create_app()
app.config['TESTING'] = True
client = app.test_client()

conn = get_db_connection()
c = conn.cursor()
p_h, salt = hash_password('ReaderPass123!')
c.execute("""
INSERT OR REPLACE INTO users (id, username, email, full_name, password_hash, salt, role, is_active, email_verified, created_at)
VALUES ('usr_test_rdr', 'test_rdr', 'test_rdr@gmail.com', 'Test Reader', ?, ?, 'READER', 1, 1, '2026-10-07T00:00:00Z')
""", (p_h, salt))
c.execute("""
INSERT OR REPLACE INTO operator_access_requests (id, user_id, email, full_name, status, requested_at)
VALUES ('req_test_rdr', 'usr_test_rdr', 'test_rdr@gmail.com', 'Test Reader', 'PENDING', '2026-10-07T12:00:00Z')
""")
conn.commit()
conn.close()

admin_token = 'test_token_admin_inspect'
ACTIVE_SESSIONS[admin_token] = {
    'id': 'usr_1084be32',
    'username': 'sakshi',
    'email': 'premkumarj18122003@gmail.com',
    'role': 'ADMIN',
    'permissions': ['*']
}

res = client.get('/api/admin/operator-requests', headers={'Authorization': f'Bearer {admin_token}'})
print('Operator-requests Status:', res.status_code)
print('Response JSON:', res.get_json())

res_users = client.get('/api/admin/users', headers={'Authorization': f'Bearer {admin_token}'})
print('Users Status:', res_users.status_code)
print('Users count:', res_users.get_json().get('count'))

conn = get_db_connection()
conn.execute("DELETE FROM operator_access_requests WHERE id = 'req_test_rdr'")
conn.execute("DELETE FROM users WHERE id = 'usr_test_rdr'")
conn.commit()
conn.close()
ACTIVE_SESSIONS.pop(admin_token, None)
