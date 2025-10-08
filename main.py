"""
insecure_smells.py

This file intentionally contains examples of poor code quality and security anti-patterns:
- Code repetition and duplication
- Feature envy (classes accessing each other's internals)
- Hard-coded secrets and insecure storage
- SQL injection via string concatenation
- Use of eval on untrusted input
- Insecure deserialization (pickle.loads)
- Weak hashing (md5) and predictable token generation
- Command injection via os.system with unsanitized input

DO NOT USE THIS CODE IN PRODUCTION. This is for educational purposes only.
"""

import sqlite3
import hashlib
import random
import os
import pickle
import requests
import json

# -------------------------------
# Hard-coded credentials (security issue)
# -------------------------------
DB_PATH = '/tmp/example.db'  # hard-coded path
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'  # plaintext password in code
API_KEY = 'sk_test_1234567890'  # hard-coded API key

# -------------------------------
# Duplicated logging functions (duplication)
# -------------------------------

def log_info(message):
    with open('/tmp/app.log', 'a') as f:
        f.write('[INFO] ' + message + '\n')


def log_error(message):
    with open('/tmp/app.log', 'a') as f:
        f.write('[ERROR] ' + message + '\n')

# Another copy of the same logging function (code repetition)
def write_log_info(msg):
    with open('/tmp/app.log', 'a') as f:
        f.write('[INFO] ' + msg + '\n')

# -------------------------------
# Database helpers with SQL injection vulnerability (string concatenation)
# -------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    conn.commit()
    conn.close()


def add_user_insecure(username, password):
    # vulnerable to SQL injection because we build SQL by concatenation
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
    c.execute(sql)
    conn.commit()
    conn.close()
    log_info('Added user ' + username)


def get_user_insecure(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # vulnerable SELECT
    sql = "SELECT id, username, password FROM users WHERE username = '%s'" % username
    c.execute(sql)
    row = c.fetchone()
    conn.close()
    return row

# -------------------------------
# Feature envy example: UserManager reaching into Session internals repeatedly
# -------------------------------

class Session:
    def __init__(self):
        self._data = {}

    def set(self, key, value):
        self._data[key] = value

    def get(self, key, default=None):
        return self._data.get(key, default)


class UserManager:
    def __init__(self, session: Session):
        self.session = session

    def login(self, username, password):
        # Instead of asking Session to do auth-related things, UserManager peeks and modifies internals
        user_row = get_user_insecure(username)
        if not user_row:
            write_log_info('Login failed for ' + username)
            return False
        user_id, user_name, stored_password = user_row
        # Very naive password check
        if stored_password == password:
            # feature envy: directly manipulating session internals
            self.session._data['user_id'] = user_id
            self.session._data['username'] = user_name
            write_log_info('User %s logged in (id=%s)' % (user_name, user_id))
            return True
        else:
            write_log_info('Password mismatch for ' + username)
            return False

    def logout(self):
        # more feature envy
        if 'user_id' in self.session._data:
            del self.session._data['user_id']
        if 'username' in self.session._data:
            del self.session._data['username']
        write_log_info('User logged out')

# -------------------------------
# Unsafe use of eval and insecure token generation
# -------------------------------


def run_user_code(code_str):
    # DANGEROUS: eval on arbitrary input
    return eval(code_str)


def generate_token_weak(username):
    # predictable token using random and md5
    r = str(random.randint(0, 999999))
    token = hashlib.md5((username + r).encode()).hexdigest()
    return token

# -------------------------------
# Insecure deserialization and command injection
# -------------------------------


def load_session_from_blob(blob):
    # DANGEROUS: untrusted pickle.loads
    try:
        session_obj = pickle.loads(blob)
        log_info('Session loaded')
        return session_obj
    except Exception as e:
        log_error('Failed to load session: %s' % str(e))
        return None


def run_shell_command(name):
    # command injection if name is not sanitized
    cmd = 'echo Hello ' + name + ' > /tmp/greeting.txt'
    os.system(cmd)
    log_info('Ran shell command for ' + name)

# -------------------------------
# Repeated business logic (duplication) for processing orders
# -------------------------------


def process_order_basic(order):
    # duplicated steps copied across functions
    if not order.get('items'):
        log_error('Order has no items')
        return False
    total = 0
    for it in order['items']:
        total += it['price'] * it.get('qty', 1)
    # duplicated validation
    if total <= 0:
        log_error('Invalid order total')
        return False
    # pretend to call external payment API insecurely
    resp = requests.post('https://payments.example.com/pay', data={'amount': total, 'api_key': API_KEY})
    write_log_info('Processed payment (basic) for order: %s' % order.get('id'))
    return resp.status_code == 200


def process_order_advanced(order):
    # the same logic duplicated with small changes
    if not order.get('items'):
        write_log_info('Order has no items (advanced)')
        return False
    total = 0
    for item in order['items']:
        total = total + item['price'] * item.get('qty', 1)
    if total <= 0:
        write_log_info('Invalid order total (advanced)')
        return False
    # different endpoint but still insecure
    resp = requests.post('http://insecure-payments.example.com/process', json={'amount': total, 'key': API_KEY})
    write_log_info('Processed payment (advanced) for order: %s' % order.get('id'))
    return resp.status_code == 200

# -------------------------------
# Utility that mixes responsibilities and duplicates functionality
# -------------------------------

def get_user_profile(uid):
    # mix DB access with formatting
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, password FROM users WHERE id = %d' % uid)
    row = c.fetchone()
    conn.close()
    if not row:
        return {}
    # duplicated conversion logic present in multiple places
    return {'id': row[0], 'username': row[1], 'password': row[2]}

# -------------------------------
# Example main to exercise functions
# -------------------------------

if __name__ == '__main__':
    init_db()
    # duplicated calls: adding same user twice without checks
    add_user_insecure('alice', 'password1')
    add_user_insecure('alice', 'password1')

    # demonstrate SQL injection (this is intentionally unsafe; do NOT run with real data)
    try:
        # This input demonstrates how someone could bypass checks or drop tables
        malicious_username = "bob'; DROP TABLE users; --"
        add_user_insecure(malicious_username, 'pw')
    except Exception as e:
        log_error('Malicious insert failed: %s' % str(e))

    session = Session()
    um = UserManager(session)
    # naive login
    um.login('alice', 'password1')

    # run arbitrary code
    try:
        result = run_user_code("__import__('os').listdir('/')")
        write_log_info('Ran user code: result length=%d' % len(result))
    except Exception as e:
        log_error('Eval failed: %s' % str(e))

    # generate weak token
    token = generate_token_weak('alice')
    print('weak token:', token)

    # insecure deserialization (do not do this)
    fake_blob = pickle.dumps({'k': 'v'})
    load_session_from_blob(fake_blob)

    # command injection example
    run_shell_command('Alice')

    # process some orders
    order = {'id': 1, 'items': [{'name': 'widget', 'price': 10, 'qty': 2}]}
    process_order_basic(order)
    process_order_advanced(order)

    # repeated profile logic
    print(get_user_profile(1))
