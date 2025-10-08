"""
insecure_smells.py

This file intentionally contains examples of poor code quality and security anti-patterns:
- Code repetition and duplication
- Feature envy (classes accessing each other's internals)
- Hard-coded secrets and insecure storage
- SQL injection via string concatenation
- Use of eval on untrusted input
import hashlib
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BS = 16  # AES block size

def pad(s):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt(data, key):
    """Encrypt data using AES-256."""
    key = hashlib.sha256(key.encode()).digest()  # Derive key using SHA-256
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(pad(data).encode('utf-8')))

def decrypt(enc, key):
    """Decrypt data using AES-256."""
    key = hashlib.sha256(key.encode()).digest()  # Derive key using SHA-256
    enc = b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
import hashlib
import secrets

def generate_token(username, password):
    """Generates a secure token using SHA-256."""
    # Use SHA-256 instead of MD5 for stronger hashing
    data = username + password
    hashed_data = hashlib.sha256(data.encode('utf-8')).hexdigest()

    # Use secrets module for more secure token generation
    token = secrets.token_hex(32)  # Generate a 32-byte (64 character) hex token

    return hashed_data + token
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
import os

# Use an environment variable for the admin password.
# Default to an empty string or a placeholder, and ensure the environment variable is set.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
import os

# Use an environment variable for the API key, providing a default value
API_KEY = os.environ.get('API_KEY', 'default_api_key')

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
                self.conn.rollback()
            self.conn.close()

    def init_db(self):
        """Initializes the database by creating the users table if it doesn't exist."""
        with self as conn: # Use context manager for connection
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')

def init_db():
    """Initializes the database using the DatabaseConnection class."""
    with DatabaseConnection(DB_PATH) as db_conn: # Use context manager
        c = db_conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')


import sqlite3

DB_PATH = 'users.db'  # Define DB_PATH here or import it

def log_info(message):
    print(message)

class DatabaseConnection:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        return self.conn.cursor()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        self.conn.close()

def add_user_insecure(username, password):
    """Adds a user to the database using vulnerable string concatenation."""
    with DatabaseConnection(DB_PATH) as c:
        sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
        c.execute(sql)
    log_info('Added user ' + username)


import sqlite3

DB_PATH = "database.db"

class DatabaseConnection:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_user_insecure(self, username):
        """
        Retrieves user data from the database based on the provided username.
        Vulnerable to SQL injection.
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
    Retrieves user data from the database based on the provided username.
    This function now uses the DatabaseConnection class.
    Vulnerable to SQL injection.
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

class SessionManager:  # Assuming 'self' refers to a session management class
    def __init__(self, session):
        self._session = session

    def logout(self):
        """Logs out the user by removing user-related data from the session."""
        self._session.clear_user_data()
        write_log_info('User logged out')

class Session:
    def __init__(self):
        self._data = {}

    def clear_user_data(self):
        """Removes user ID and username from the session data."""
        if 'user_id' in self._data:
            del self._data['user_id']
        if 'username' in self._data:
            del self._data['username']

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
        r = str(random.randint(0, 999999))
import hashlib

def generate_token(username, r):
    """
    Generates a token using SHA-256 instead of MD5 for improved security.
    """
    token = hashlib.sha256((username + r).encode()).hexdigest()  # Use SHA-256 for token generation
    return token
        return token

def generate_token_weak(username):
    # Delegate token generation to the TokenGenerator class
    return TokenGenerator.generate_token_weak(username)

# -------------------------------
import hashlib
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class CryptoUtils:
    def __init__(self, secret_key):
        self.key = hashlib.sha256(secret_key.encode()).digest()  # Derive a 256-bit key from the secret
        self.block_size = AES.block_size  # Block size for AES

    def encrypt(self, data):
        """Encrypts data using AES-256 with PKCS7 padding."""
        iv = os.urandom(self.block_size)  # Generate a random initialization vector
        cipher = AES.new(self.key, AES.MODE_CBC, iv)  # Use AES in CBC mode
        padded_data = pad(data.encode(), self.block_size)  # Pad the data to be a multiple of the block size
        encrypted_data = cipher.encrypt(padded_data)
        return b64encode(iv + encrypted_data).decode()  # Prepend IV and encode to base64

    def decrypt(self, data):
        """Decrypts data using AES-256 with PKCS7 padding."""
        try:
            data = b64decode(data)
            iv = data[:self.block_size]  # Extract the IV from the beginning
            cipher = AES.new(self.key, AES.MODE_CBC, iv)  # Use AES in CBC mode
            decrypted_data = cipher.decrypt(data[self.block_size:])
            unpadded_data = unpad(decrypted_data, self.block_size)  # Remove padding
            return unpadded_data.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
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


import requests

API_KEY = '12345'  # nosec


def log_error(message):
    print(f"ERROR: {message}")


def write_log_info(message):
    print(f"INFO: {message}")


class Order:
    def __init__(self, order_data):
        self.order_data = order_data
        self.id = order_data.get('id')
        self.items = order_data.get('items')

    def calculate_total(self):
        """Calculates the total order value."""
        total = 0
        if self.items:
            for item in self.items:
                total += item['price'] * item.get('qty', 1)
        return total

    def is_valid_total(self, total):
        """Validates if the total order value is valid."""
        return total > 0

    def process_payment(self):
        """Processes the payment for the order."""
        total = self.calculate_total()

        if not self.items:
            log_error('Order has no items')
            return False

        if not self.is_valid_total(total):
            log_error('Invalid order total')
            return False

        # pretend to call external payment API insecurely
        resp = requests.post('https://payments.example.com/pay', data={'amount': total, 'api_key': API_KEY})
        write_log_info('Processed payment (basic) for order: %s' % self.id)
        return resp.status_code == 200


def process_order_basic(order_data):
    """Processes a basic order using the Order class."""
    order = Order(order_data)
    return order.process_payment()


import requests

API_KEY = "your_api_key_here"

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
            return 0
        total = 0
        for item in self.items:
            total += item['price'] * item.get('qty', 1)
        return total

    def process_payment(self):
        """Processes the payment for the order."""
        total = self.calculate_total()
        if total <= 0:
            write_log_info('Invalid order total')
            return False
        # Insecure endpoint
        resp = requests.post('http://insecure-payments.example.com/process', json={'amount': total, 'key': API_KEY})
        write_log_info('Processed payment for order: %s' % self.id)
        return resp.status_code == 200

def process_order_advanced(order_data):
    """Processes the advanced order using the Order class."""
    order = Order(order_data)
    return order.process_payment()

# -------------------------------
# Utility that mixes responsibilities and duplicates functionality
# -------------------------------

import sqlite3

DB_PATH = 'user.db'

class UserDB:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_user_profile(self, uid):
        """
        Retrieves a user profile from the database based on the user ID.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute('SELECT id, username, password FROM users WHERE id = ?', (uid,)) # Use parameterized query
            row = c.fetchone()

            if not row:
                return {}

            return self._convert_row_to_dict(row) # Use helper method

        finally:
            conn.close()

    def _convert_row_to_dict(self, row):
        """
        Converts a database row to a user profile dictionary.
        """
        return {'id': row[0], 'username': row[1], 'password': row[2]}


_user_db = UserDB(DB_PATH) # Instantiate the database connection

def get_user_profile(uid):
    """
    Retrieves a user profile using the UserDB class.
    """
    return _user_db.get_user_profile(uid)

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
import os

# Use an environment variable to store the token
token = os.environ.get("API_TOKEN")

# Check if the environment variable is set
if token is None:
    raise ValueError("API_TOKEN environment variable not set.")

import os

# Use an environment variable for the token
token = os.environ.get("API_TOKEN")

# Handle the case where the environment variable is not set
if token is None:
    print("Error: API_TOKEN environment variable not set.")
else:
import logging

def sanitize_token(token: str) -> str:
    """
    Sanitizes a token by redacting most of it, leaving only the first and last 4 characters visible.
    If the token is shorter than 8 characters, it returns a fully redacted string.
    """
    if len(token) <= 8:
        return "REDACTED"
    else:
        return token[:4] + "..." + token[-4:]

# Configure logging (consider setting level based on environment)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def process_token(token: str):
    """
    Processes a token and logs a sanitized version.
    """
    sanitized_token = sanitize_token(token)
    logging.info(f"Sanitized token: {sanitized_token}") # Log the sanitized token

import hashlib
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


class AESCipher:
    def __init__(self, key):
        # Ensure the key is bytes
        if isinstance(key, str):
            key = key.encode('utf-8')

        # Hash the key to ensure it's the correct length (32 bytes for AES-256)
        hashed_key = hashlib.sha256(key).digest()
        self.key = hashed_key

    def encrypt(self, data):
        # Ensure the data is bytes
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Generate a random initialization vector (IV)
        iv = os.urandom(16)

        # Pad the data to be a multiple of the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Create an AES cipher object in CBC mode with the key and IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return the IV and ciphertext, base64 encoded
        return b64encode(iv + ciphertext).decode('utf-8')

    def decrypt(self, data):
        # Decode the base64 encoded data
        data = b64decode(data)

        # Extract the IV from the beginning of the data
        iv = data[:16]

        # Extract the ciphertext from the rest of the data
        ciphertext = data[16:]

        # Create an AES cipher object in CBC mode with the key and IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        # Return the decrypted data as a string
        return data.decode('utf-8')
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
