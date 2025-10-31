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

import sqlite3

DB_PATH = 'users.db'

class DatabaseConnection:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()  # Rollback on exception
            self.conn.close()

    def init_db(self):
        """Initializes the database with the users table."""
        with DatabaseConnection(self.db_path) as conn:
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')


def init_db():
    """Initializes the database using the DatabaseConnection class."""
    db_conn = DatabaseConnection(DB_PATH)
    db_conn.init_db()


import sqlite3

DB_PATH = 'users.db'

def log_info(message):
    print(message)

class DatabaseConnection:
    def __init__(self, db_path):
        self.db_path = db_path

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.cursor.close()
        self.conn.close()

    def execute(self, sql, params=None):
        if params:
            self.cursor.execute(sql, params)
        else:
            self.cursor.execute(sql)

    def add_user_insecure(self, username, password):
        # vulnerable to SQL injection because we build SQL by concatenation
        sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
        self.execute(sql)
        log_info('Added user ' + username)


def add_user_insecure(username, password):
    with DatabaseConnection(DB_PATH) as db_conn:
        db_conn.add_user_insecure(username, password)


import sqlite3

DB_PATH = "db.sqlite"

class DatabaseConnection:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_user_insecure(self, username):
        """
        Retrieves user data from the database based on the provided username (INSECURE).
        This method is vulnerable to SQL injection and should not be used in production.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # vulnerable SELECT
        sql = "SELECT id, username, password FROM users WHERE username = '%s'" % username
        c.execute(sql)
        row = c.fetchone()
        conn.close()
        return row


def get_user_insecure(username):
    """
    Retrieves user data from the database based on the provided username (INSECURE).
    This method is vulnerable to SQL injection and should not be used in production.
    """
    db_conn = DatabaseConnection(DB_PATH)
    return db_conn.get_user_insecure(username)

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

class SessionManager:
    def __init__(self, session):
        self.session = session

    def logout(self):
        """Logs out the user by removing user-related data from the session."""
        self._clear_user_session_data()
        write_log_info('User logged out')

    def _clear_user_session_data(self):
        """Removes user_id and username from the session data."""
        if 'user_id' in self.session._data:
            del self.session._data['user_id']
        if 'username' in self.session._data:
            del self.session._data['username']

# -------------------------------
# Unsafe use of eval and insecure token generation
# -------------------------------


def run_user_code(code_str):
    # DANGEROUS: eval on arbitrary input
    return eval(code_str)


import hashlib
import random

class TokenGenerator:
    @staticmethod
    def generate_token_weak(username):
        """Generates a weak token using random and md5."""
        random_number = str(random.randint(0, 999999))
        # Generate the token using hashlib
        token = hashlib.md5((username + random_number).encode()).hexdigest()
        return token

def generate_token_weak(username):
    """Generates a weak token using random and md5."""
    return TokenGenerator.generate_token_weak(username)

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


class Order:
    def __init__(self, order_data):
        self.data = order_data
        self.id = order_data.get('id')
        self.items = order_data.get('items', [])

    def calculate_total(self):
        """Calculates the total order amount."""
        total = 0
        for item in self.items:
            total += item['price'] * item.get('qty', 1)
        return total

    def is_valid(self):
        """Validates the order to ensure it has items and a positive total."""
        if not self.items:
            log_error('Order has no items')
            return False
        total = self.calculate_total()
        if total <= 0:
            log_error('Invalid order total')
            return False
        return True

    def process_payment(self):
        """Processes the payment for the order."""
        total = self.calculate_total()
        resp = requests.post('https://payments.example.com/pay', data={'amount': total, 'api_key': API_KEY})
        write_log_info('Processed payment (basic) for order: %s' % self.id)
        return resp.status_code == 200


def process_order_basic(order_data):
    """Processes an order using the Order class."""
    order = Order(order_data)
    if not order.is_valid():
        return False
    return order.process_payment()


import requests

API_KEY = "your_actual_api_key"  # Replace with your actual API key

def write_log_info(log_message):
    print(log_message)

class Order:
    def __init__(self, order_data):
        self.order_data = order_data
        self.id = order_data.get('id')
        self.items = order_data.get('items')

    def calculate_total(self):
        """Calculates the total order amount."""
        if not self.items:
            write_log_info('Order has no items')
            return False, 0
        total = 0
        for item in self.items:
            total = total + item['price'] * item.get('qty', 1)
        if total <= 0:
            write_log_info('Invalid order total')
            return False, 0
        return True, total

    def process_payment(self, total, endpoint):
        """Processes the payment for the order."""
        resp = requests.post(endpoint, json={'amount': total, 'key': API_KEY})
        return resp.status_code == 200

    def process_order_advanced(self):
        """Processes the order with advanced payment processing."""
        success, total = self.calculate_total()
        if not success:
            return False

        # Different endpoint but still insecure
        resp_status = self.process_payment(total, 'http://insecure-payments.example.com/process')
        write_log_info('Processed payment (advanced) for order: %s' % self.id)
        return resp_status

def process_order_advanced(order_data):
    """Processes the order with advanced payment processing."""
    order = Order(order_data)
    return order.process_order_advanced()

# -------------------------------
# Utility that mixes responsibilities and duplicates functionality
# -------------------------------

import sqlite3

DB_PATH = 'user.db'

class UserDB:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_user_profile(self, uid):
        """Retrieves a user profile from the database by user ID."""
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute('SELECT id, username, password FROM users WHERE id = ?', (uid,)) # Use parameterized query to avoid SQL injection
            row = c.fetchone()
            if not row:
                return {}
            return self._convert_row_to_dict(row) # call helper to format
        finally:
            conn.close()

    def _convert_row_to_dict(self, row):
        """Converts a database row to a user profile dictionary."""
        return {'id': row[0], 'username': row[1], 'password': row[2]}


def get_user_profile(uid):
    """Retrieves a user profile from the database by user ID."""
    user_db = UserDB(DB_PATH)
    return user_db.get_user_profile(uid)

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
