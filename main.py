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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class EncryptionService:
    def __init__(self, secret_key):
        self.key = hashlib.sha256(secret_key.encode()).digest()  # Derive key using SHA256

    def encrypt(self, data: str) -> str:
        """Encrypts data using AES-256 with CBC mode and PKCS7 padding."""
        iv = os.urandom(16)  # Generate a random 16-byte IV
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return b64encode(iv + ciphertext).decode('utf-8') #Return base64 encoded string

    def decrypt(self, data: str) -> str:
        """Decrypts data encrypted with AES-256 CBC mode and PKCS7 padding."""
        encrypted_data = b64decode(data)
        iv = encrypted_data[:16] # Extract IV from the beginning
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data.decode('utf-8')
import hashlib
import secrets

def generate_token(username, password):
    """
    Generates a secure token using SHA-256.
    """
    # Use SHA-256 instead of MD5 for stronger hashing
    combined_string = username + password + secrets.token_hex(16)
    hashed_string = hashlib.sha256(combined_string.encode('utf-8')).hexdigest()
    return hashed_string

def verify_token(username, password, token):
    """
    Verifies the token against the provided username and password using SHA-256.
    """
    # Recreate the hash using SHA-256 for comparison
    combined_string = username + password
    
    # Iterate through possible secrets to check for match, mitigating predictability.
    for i in range(10): #check 10 possible secret combinations
        potential_secret = secrets.token_hex(16)
        potential_combined_string = combined_string + potential_secret
        potential_hashed_string = hashlib.sha256(potential_combined_string.encode('utf-8')).hexdigest()

        if potential_hashed_string == token:
            return True
            
    return False
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

# Use environment variables for sensitive information
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise ValueError("ADMIN_PASSWORD environment variable not set.")
import os

# API_KEY is now loaded from an environment variable
API_KEY = os.environ.get('API_KEY')

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
        """Initializes the database with the users table."""
        with DatabaseConnection(self.db_path) as conn:  # Use context manager
            c = conn.cursor()
            c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')


def init_db():
    """Initializes the database using the DatabaseConnection class."""
    db_conn = DatabaseConnection(DB_PATH)
    db_conn.init_db()


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

class SessionManager:  # Assuming 'self' is an instance of a SessionManager-like class
    def __init__(self, session_data):
        self._data = session_data

    def logout(self):
        """
        Logs out the user by removing user-related data from the session.
        """
        if 'user_id' in self._data:
            del self._data['user_id']
        if 'username' in self._data:
            del self._data['username']
        write_log_info('User logged out')

# Example usage (assuming you have an instance of SessionManager)
# session_manager = SessionManager(session._data)
# session_manager.logout()

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
        """Generates a predictable token using random and md5.

        Args:
            username (str): The username to generate the token for.

        Returns:
            str: The generated token.
        """
        r = str(random.randint(0, 999999))
import hashlib

def generate_token(username, r):
    """
    Generates a token using SHA-256 for enhanced security.
    Replaces the insecure MD5 algorithm.
    """
    token = hashlib.sha256((username + r).encode()).hexdigest()
    return token
        return token

# -------------------------------
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidTag
import base64


def generate_salt():
    """Generates a random salt for key derivation."""
    return os.urandom(16)


def generate_key(password, salt):
    """Generates a key from the password and salt using PBKDF2-HMAC-SHA256."""
    kdf = hashes.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt(data, password):
    """Encrypts the data using AES-256 with GCM."""
    salt = generate_salt()
    key = generate_key(password, salt)
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    
    # Include the GCM tag
    tag = encryptor.tag

    # Return all the components needed for decryption (salt, iv, ciphertext, tag)
    return base64.b64encode(salt + iv + tag + ciphertext).decode()


def decrypt(encrypted_data, password):
    """Decrypts the data using AES-256 with GCM."""
    # Decode the base64 encoded data
    encrypted_data = base64.b64decode(encrypted_data)

    # Extract salt, iv, tag, and ciphertext
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    tag = encrypted_data[32:48]
    ciphertext = encrypted_data[48:]

    key = generate_key(password, salt)

    # Initialize the AES GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    try:
        data = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError("Invalid password or corrupted data.")

    return data.decode()


if __name__ == '__main__':
    password = "my_secret_password"
    data = "Sensitive data to be encrypted"

    encrypted_data = encrypt(data, password)
    print("Encrypted:", encrypted_data)

    decrypted_data = decrypt(encrypted_data, password)
    print("Decrypted:", decrypted_data)
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

API_KEY = "VERY_SECRET_KEY"

def log_error(msg):
    print(f"[ERROR] {msg}")

def write_log_info(msg):
    print(f"[INFO] {msg}")

class Order:
    def __init__(self, order_data):
        self.order_data = order_data
        self.id = order_data.get('id')
        self.items = order_data.get('items')

    def calculate_total(self):
        """Calculates the total order amount."""
        if not self.items:
            log_error('Order has no items')
            return None
        total = 0
        for item in self.items:
            total += item['price'] * item.get('qty', 1)
        return total

    def process_payment_basic(self):
        """Processes the order payment using a basic method."""
        total = self.calculate_total()
        if total is None:
            return False

        if total <= 0:
            log_error('Invalid order total')
            return False

        # Pretend to call external payment API insecurely
        resp = requests.post('https://payments.example.com/pay', data={'amount': total, 'api_key': API_KEY})
        write_log_info('Processed payment (basic) for order: %s' % self.id)
        return resp.status_code == 200


def process_order_basic(order_data):
    """Processes an order using the Order class."""
    order = Order(order_data)
    return order.process_payment_basic()


import requests

API_KEY = "your_actual_api_key"  # Replace with a real API key

def write_log_info(message):
    print(message)  # Simplified logging for demonstration

class Order:
    def __init__(self, order_data):
        self.order_data = order_data
        self.id = order_data.get('id')
        self.items = order_data.get('items')

    def calculate_total(self):
        """Calculates the total order amount."""
        if not self.items:
            write_log_info('Order has no items')
            return None
        total = 0
        for item in self.items:
            total = total + item['price'] * item.get('qty', 1)
        if total <= 0:
            write_log_info('Invalid order total')
            return None
        return total

    def process_payment(self):
        """Processes the payment for the order."""
        total = self.calculate_total()
        if total is None:
            return False

        # Insecure endpoint - this is intentional for demonstration
        resp = requests.post('http://insecure-payments.example.com/process', json={'amount': total, 'key': API_KEY})
        write_log_info('Processed payment for order: %s' % self.id)
        return resp.status_code == 200


def process_order_advanced(order_data):
    """Processes an order with advanced features."""
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
            c.execute('SELECT id, username, password FROM users WHERE id = ?', (uid,))
            row = c.fetchone()
            if not row:
                return {}
            return self._create_user_profile(row) # Use helper method
        finally:
            conn.close()

    def _create_user_profile(self, row):
        """
        Helper method to create a user profile dictionary from a database row.
        """
        return {'id': row[0], 'username': row[1], 'password': row[2]}

def get_user_profile(uid):
    """
    Retrieves a user profile from the database based on the user ID.
    """
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
import os

# Use an environment variable to store the token
TOKEN = os.environ.get("API_TOKEN")

if TOKEN:
    print('Token:', TOKEN)
else:
    print('API_TOKEN environment variable not set.')

import hashlib
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher:
    def __init__(self, key):
        """
        Initializes the AESCipher with a key.
        The key is hashed using SHA-256 to ensure it's 32 bytes long for AES-256.
        """
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, data):
        """
        Encrypts the given data using AES-256 with PKCS7 padding.
        A random initialization vector (IV) is generated for each encryption.
        The IV is prepended to the ciphertext for decryption.
        """
        iv = os.urandom(AES.block_size)  # Generate a random IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode(), AES.block_size)  # Apply PKCS7 padding
        ciphertext = cipher.encrypt(padded_data)
        return b64encode(iv + ciphertext).decode('utf-8')  # Prepend IV and encode

    def decrypt(self, data):
        """
        Decrypts the given data using AES-256.
        The IV is extracted from the beginning of the ciphertext.
        """
        try:
            encrypted_data = b64decode(data)
            iv = encrypted_data[:AES.block_size]  # Extract the IV
            ciphertext = encrypted_data[AES.block_size:]  # Extract the ciphertext
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)  # Remove padding
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
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
