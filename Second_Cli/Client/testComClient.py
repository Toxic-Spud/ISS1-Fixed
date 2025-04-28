from os import urandom
from Crypto.PublicKey import ECC
from communicate import Communicate
from pyotp import TOTP
import hashlib
from os import urandom
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from communicate import Communicate
from pyotp import TOTP
import hashlib
import json




def generate_keys():
    """Generate ECC keys for communication and signing."""
    com_key = ECC.generate(curve="P-256").export_key(format="DER")
    sig_key = ECC.generate(curve="P-256").export_key(format="DER")
    return com_key, sig_key


def test_sign_up(connection):
    print("Running test: Sign Up")
    username = "testUser"
    password = "TestPassword123!"  # Updated to meet password requirements
    com_key, sig_key = generate_keys()
    connection.send("signup", [username, password, com_key, sig_key], None)
    response = connection.get_message()
    assert response[0] == "totp", f"Sign up failed: {response}"
    print(f"Sign up successful! TOTP Secret: {response[1][0]}")
    return username, password, response[1][0]  # Return username, password, and TOTP secret


def test_login(connection, username, password, totp_secret):
    print("Running test: Login")
    # Generate the TOTP code
    totp = TOTP(totp_secret, interval=30, digits=8, digest=hashlib.sha256).now()
    
    # Send login request
    connection.send("login", [username.encode(), password.encode(), totp.encode()], None)
    response = connection.get_message()
    
    # Ensure the response indicates success
    assert response[0] == "succ", f"Login failed: {response}"
    
    # Extract session ID and user details
    session_id = response[1][0].decode("utf-8")  # Decode the session ID
    user_details = json.loads(response[1][1].decode("utf-8"))  # Parse the JSON-dumped user details
    user_id = user_details["id"]  # Extract the user ID from the parsed details
    
    print(f"Login successful! Session ID: {session_id}, User ID: {user_id}")
    return session_id, user_id


def test_send_message(connection, session_id):
    print("Running test: Send Message")
    connection.send("send", ["Hello, this is a test message!", session_id], session_id)
    response = connection.get_message()
    assert response[0] == "succ", f"Send message failed: {response}"
    print("Message sent successfully!")



def test_send_message_no_employee(connection, session_id):
    print("Running test: Send Message (No Assigned Employee)")
    connection.send("send", ["Hello, this is a test message!", session_id], session_id)
    response = connection.get_message()
    assert response[0] == "fail", f"Expected failure due to no assigned employee, but got: {response}"
    print("Message test passed: No assigned employee.")


def test_get_history(connection, session_id, account_id):
    print("Running test: Get History")
    connection.send("hist", [str(account_id)], session_id)
    response = connection.get_message()
    assert response[0] == "succ", f"Get history failed: {response}"
    history = response[1:]
    print("History retrieved successfully!")
    for record in history:
        print(record.decode("utf-8"))

def test_buy_stocks(connection, session_id, account_id):
    print("Running test: Buy Stocks")
    stock_id = "1"  # Replace with a valid stock ID
    amount = "5"  # Number of stocks to buy
    action = "b"  # 'b' for buy
    transaction_id = urandom(16).hex()  # Generate a unique transaction ID
    key = ECC.generate(curve="P-256")
    signature = DSS.new(key, "fips-186-3").sign(SHA256.new(bytes(account_id + stock_id + amount + action + transaction_id, "utf-8")))
    connection.send("tran", [account_id, stock_id, amount, action, signature, transaction_id], session_id)
    response = connection.get_message()
    assert response[0] == "succ", f"Buy stocks failed: {response}"
    print("Stocks bought successfully!")

def test_sell_stocks(connection, session_id, account_id):
    print("Running test: Sell Stocks")
    stock_id = "1"  # Replace with a valid stock ID
    amount = "3"  # Number of stocks to sell
    action = "s"  # 's' for sell
    transaction_id = urandom(16).hex()  # Generate a unique transaction ID
    key = ECC.generate(curve="P-256")
    signature = DSS.new(key, "fips-186-3").sign(SHA256.new(bytes(account_id + stock_id + amount + action + transaction_id, "utf-8")))
    connection.send("tran", [account_id, stock_id, amount, action, signature, transaction_id], session_id)
    response = connection.get_message()
    assert response[0] == "succ", f"Sell stocks failed: {response}"
    print("Stocks sold successfully!")
print("Starting tests")
connection = Communicate()
connection.initiate_handshake()
username, password, totp_secret = test_sign_up(connection)
session_id, account_id = test_login(connection, username, password, totp_secret)
test_get_history(connection, session_id, account_id)
test_buy_stocks(connection, session_id, account_id)
test_sell_stocks(connection, session_id, account_id)
test_send_message(connection, session_id)