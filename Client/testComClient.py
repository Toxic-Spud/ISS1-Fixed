from os import urandom
from Crypto.PublicKey import ECC
from communicate import Communicate
from pyotp import TOTP
import hashlib
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import json


def generate_keys():
    """Generate ECC keys for communication and signing."""
    com_key = ECC.generate(curve="P-256")
    sig_key = ECC.generate(curve="P-256")
    return com_key, sig_key


def test_sign_up(connection):
    print("Running test: Sign Up")
    username = f"testUser_{urandom(4).hex()}"  # Generate a unique username
    password = "TestPassword123!"  # Ensure the password meets requirements
    com_key, sig_key = generate_keys()
    
    # Send sign-up request
    connection.send("sign", [username, password, com_key.public_key().export_key(format="DER"), sig_key.public_key().export_key(format="DER")])
    response = connection.get_message()
    
    # Handle server response
    assert response[0] == "totp", f"Sign up failed: {response[0].decode('utf-8') if isinstance(response[0], bytes) else response[0]}"
    totp_secret = response[1].decode("utf-8")  # Decode the TOTP secret
    print(f"Sign up successful! Username: {username}, TOTP Secret: {totp_secret}")
    return username, password, totp_secret, com_key.export_key(format="DER"), sig_key.export_key(format="DER")


def test_login(connection: Communicate, username, password, totp_secret):
    print("Running test: Login")
    # Generate the TOTP code
    totp = TOTP(totp_secret, interval=30, digits=8, digest=hashlib.sha256).now()
    
    # Send login request
    connection.send("clog", [username.encode(), password.encode(), totp.encode()], None)
    response = connection.get_message()
    
    # Ensure the response indicates success
    assert response[0] == "succ", f"Login failed: {response[0].decode('utf-8') if isinstance(response[0], bytes) else response[0]}"
    
    # Extract session ID and user details
    connection.sessionId = response[1].decode("utf-8")
    session_id = response[1].decode("utf-8")  # Decode the session ID
    user_details = json.loads(response[2].decode("utf-8"))  # Parse the JSON-dumped user details
    user_id = user_details["id"]  # Extract the user ID from the parsed details
    
    print(f"Login successful! Session ID: {session_id}, User ID: {user_id}")
    return session_id, user_id


def test_get_history(connection, session_id, account_id):
    print("Running test: Get History")
    connection.send("hist", [str(account_id)], session_id)
    response = connection.get_message()
    
    # Ensure the response indicates success
    assert response[0] == "succ", f"Get history failed: {response[0].decode('utf-8') if isinstance(response[0], bytes) else response[0]}"
    
    # Decode and print the history
    history = [record.decode("utf-8") for record in response[1:]]
    print("History retrieved successfully!")
    for record in history:
        print(record)


def test_buy_stocks(connection, session_id, account_id, sig_key):
    print("Running test: Buy Stocks")
    stock_id = "1"  # Replace with a valid stock ID
    amount = "5"  # Number of stocks to buy
    action = "b"  # 'b' for buy
    transaction_id = urandom(16).hex()  # Generate a unique transaction ID
    
    # Use the signing key from sign-up
    key = ECC.import_key(sig_key)
    signature = DSS.new(key, "fips-186-3").sign(SHA256.new(bytes(account_id + stock_id + amount + action + account_id + transaction_id, "utf-8")))
    
    # Send buy request
    connection.send("tran", [account_id, stock_id, amount, action, signature, transaction_id], session_id)
    response = connection.get_message()
    
    # Ensure the response indicates success
    assert response[0] == "succ", f"Buy stocks failed: {response[0].decode('utf-8') if isinstance(response[0], bytes) else response[0]}"
    print("Stocks bought successfully!")


def test_sell_stocks(connection, session_id, account_id, sig_key):
    print("Running test: Sell Stocks")
    stock_id = "1"  # Replace with a valid stock ID
    amount = "3"  # Number of stocks to sell
    action = "s"  # 's' for sell
    transaction_id = urandom(16).hex()  # Generate a unique transaction ID
    
    # Use the signing key from sign-up
    key = ECC.import_key(sig_key)
    signature = DSS.new(key, "fips-186-3").sign(SHA256.new(bytes(account_id + stock_id + amount + action +account_id + transaction_id, "utf-8")))
    
    # Send sell request
    connection.send("tran", [account_id, stock_id, amount, action, signature, transaction_id], session_id)
    response = connection.get_message()
    
    # Ensure the response indicates success
    assert response[0] == "succ", f"Sell stocks failed: {response[0].decode('utf-8') if isinstance(response[0], bytes) else response[0]}"
    print("Stocks sold successfully!")

def test_employee_sign_up_and_login(connection, employee_username, employee_code):
    print("Running test: Employee Sign-Up and Login")
    
    # Sign up as the employee
    print("Signing up as the employee...")
    password = employee_code
    com_key, sig_key = generate_keys()
    connection.send("emps", [employee_code, employee_username, password, com_key.public_key().export_key(format="DER"), sig_key.public_key().export_key(format="DER")])
    response = connection.get_message()
    assert response[0] == "totp", f"Failed to sign up as employee: {response[1].decode('utf-8')}"
    totp_secret = response[1].decode("utf-8")
    print(f"Employee signed up successfully! TOTP Secret: {totp_secret}")
    
    # Log in as the employee
    print("Logging in as the employee...")
    session_id, employee_id = test_login(connection, employee_username, password, totp_secret)
    print(f"Employee logged in successfully! Employee ID: {employee_id}")
    
    return session_id, str(employee_id), totp_secret, employee_id, sig_key


def test_employee_functionality(connection, session_id, employeeId, sig_key):
    print("Running test: Employee Functionality")
    
    # Test employee functionality (e.g., get assigned customers)
    print("Testing employee functionality...")
    connection.send("lcus", [session_id])
    response = connection.get_message()
    assert response[0] == "succ", f"Failed to retrieve assigned customers: {response[1].decode('utf-8')}"
    assigned_customers = [customer.decode("utf-8") for customer in response[1:]]
    print("Assigned customers retrieved successfully!")
    for customer in assigned_customers:
        print(customer)
    
    # Ensure at least one customer is assigned for further tests
    assert len(assigned_customers) > 0, "No customers assigned to the employee for further testing."
    test_customer_id = assigned_customers[0].split(",")[0][1:]  # Extract the customer ID from the response
    
    
    # Test performing a transaction on behalf of the customer
    print(f"Testing performing a transaction on behalf of customer {test_customer_id}...")
    stock_id = "1"  # Replace with a valid stock ID
    amount = "10"  # Number of stocks to buy
    action = "b"  # 'b' for buy
    transaction_id = urandom(16).hex()  # Generate a unique transaction ID
    
    # Use the signing key to sign the transaction
    key = sig_key
    signed_data = test_customer_id + stock_id + amount + action+ str(employeeId) + transaction_id
    signature = DSS.new(key, "fips-186-3").sign(SHA256.new(bytes(signed_data, "utf-8")))
    
    # Send the transaction request
    connection.send("tran", [test_customer_id, stock_id, amount, action, signature, transaction_id, session_id])
    response = connection.get_message()
    assert response[0] == "succ", f"Failed to perform transaction for customer: {response[1].decode('utf-8')}"
    print("Transaction performed successfully!")
    
    
    print(f"Running test: Employee Get Customer History for Customer ID {test_customer_id}")
    
    # Send request to get customer history
    connection.send("hist", [test_customer_id, session_id])
    response = connection.get_message()
    
    # Ensure the response indicates success
    assert response[0] == "succ", f"Failed to retrieve customer history: {response[1].decode('utf-8')}"
    
    # Decode and print the history
    history = [record.decode("utf-8") for record in response[1:]]
    print("Customer history retrieved successfully!")
    for record in history:
        print(record)

    
    return True


def test_admin_tasks(connection, admin_username, test_customer_id):
    print("Running test: Admin Tasks")
    
    # Log in as admin
    admin_code = str(input("Enter the devAdmin code: "))
    session_id = test_employee_sign_up_and_login(connection, admin_username, admin_code)
    session_id = session_id[0]
    
    # Create a new employee
    print("Creating a new employee...")
    employee_username = f"employee_{urandom(4).hex()}"
    connection.send("nemp", [employee_username, "finance advisor", session_id])
    response = connection.get_message()
    assert response[0] == "succ", f"Failed to create employee: {response[1].decode('utf-8')}"
    employee_code = response[1].decode("utf-8")
    print(f"Employee created successfully! Username: {employee_username}, Code: {employee_code}")
    
    # Employee signs up and logs in to retrieve their ID and TOTP secret
    employee_session_id, employee_id, employee_totp_secret, comKey, sigKey = test_employee_sign_up_and_login(connection, employee_username, employee_code)
    
    # Assign the employee to the test customer using the admin's session ID
    print("Assigning the employee to the test customer...")
    connection.send("asig", [employee_id, test_customer_id,session_id])
    response = connection.get_message()
    assert response[0] == "succ", f"Failed to assign employee to customer: {response[1].decode('utf-8')}"
    print("Employee assigned to test customer successfully!")
    
    # Deactivate the employee
    print("Deactivating the employee...")
    connection.send("deac", [employee_id, session_id])
    response = connection.get_message()
    assert response[0] == "succ", f"Failed to deactivate employee: {response[1].decode('utf-8')}"
    print("Employee deactivated successfully!")
    
    # Reactivate the employee
    print("Reactivating the employee...")
    connection.send("acti", [employee_id, session_id])
    response = connection.get_message()
    assert response[0] == "succ", f"Failed to reactivate employee: {response[1].decode('utf-8')}"
    print("Employee reactivated successfully!")
    
    # Get logs
    print("Getting logs...")
    connection.send("glog", [session_id])
    info_log = connection.get_message()
    assert info_log[0] == "succ", f"Failed to retrieve info logs: {info_log[1].decode('utf-8')}"
    print("Info logs retrieved successfully!")
    sec_log = connection.get_message()
    assert sec_log[0] == "succ", f"Failed to retrieve security logs: {sec_log[1].decode('utf-8')}"
    print("Security logs retrieved successfully!")
    
    # Revoke and rekey the database
    print("Revoking and rekeying the database...")
    connection.send("revk", ["data", session_id])
    response = connection.get_message()
    assert response[0] == "succ", f"Failed to revoke and rekey database: {response[1].decode('utf-8')}"
    print("Database revoked and rekeyed successfully!")
    
    # Backup the database
    print("Backing up the database...")
    connection.send("back", [session_id])
    response = connection.get_message()
    assert response[0] == "succ", f"Failed to backup database: {response[1].decode('utf-8')}"
    print("Database backed up successfully!")
    
    return employee_session_id, comKey, sigKey, session_id


# Main test execution
print("Starting tests")
connection = Communicate()
connection.initiate_handshake()

# Run the tests
username, password, totp_secret, com_key, sig_key = test_sign_up(connection)
session_id, account_id = test_login(connection, username, password, totp_secret)
account_id = str(account_id)
test_buy_stocks(connection, session_id, account_id, sig_key)
test_sell_stocks(connection, session_id, account_id, sig_key)
test_get_history(connection, session_id, account_id)

# Admin tasks
admin_username = "devAdmin"
test_customer_id = account_id
employee_session_id, employee_com_key, employee_sig_key, admin_session_id = test_admin_tasks(connection, admin_username, test_customer_id)

# Employee functionality
test_employee_functionality(connection, employee_session_id, employee_com_key, employee_sig_key)