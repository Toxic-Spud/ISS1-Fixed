
from time import sleep
from random import randint
from ServerCrypto import check_pass
from Lockout import IP_LOCKOUT, IP_USER_LOCKOUT, USER_LOCKOUT
from database import AUTH_DATA_BASE, User
from log import INFO_LOGGER, ALERT_LOGGER
import hashlib
from pyotp import TOTP
from datetime import datetime as dTime, timedelta
from communicate import Communicate
from ServerCrypto import new_password, new_TOTP, verify_signature, create_code, check_code
import json
from os import urandom
from datetime import datetime, timedelta


class RBAC:
    failed = 0
    lastRecorded = None
    @classmethod
    def transaction(cls, connection:Communicate,sessionId:str, account:str):
        try:
            user:User = connection.get_session_data(sessionId)["user"]
            assigned = AUTH_DATA_BASE.assigned_to_employee(user.id, account)
        except:
            cls.failed += 1
            cls.log_bruteforce()
            return False
        if not user.active:
            cls.failed += 1
            cls.log_bruteforce()
            return False
        if int(account) == user.id and user.role == "customer":
            return True
        if assigned and user.role == "finance advisor":
            return True
        else:
            cls.failed += 1
            cls.log_bruteforce()
            return False
    
    @classmethod
    def log_bruteforce(cls):
        if cls.lastRecorded == None:
            cls.lastRecorded = datetime.now()
        if cls.failed >= 100 and cls.lastRecorded+timedelta(minutes=5) > datetime.now():
            ALERT_LOGGER.warn("High volume of invalid session IDs possible brute force")
            cls.failed = 0
        cls.lastRecorded = datetime.now()


    @classmethod
    def get_message(cls, connection:Communicate, sessionId:str, recipient:str):
        try:
            user:User = connection.get_session_data(sessionId)["user"]
            assigned = AUTH_DATA_BASE.assigned_to_employee(user.id, recipient)
            assignedEmployee = AUTH_DATA_BASE.get_assigned_employee(user.id)
        except:
            cls.failed += 1
            cls.log_bruteforce()
            return False
        if not user.active:
            cls.failed += 1
            cls.log_bruteforce()
            return False
        if int(recipient) == assignedEmployee:
            return True
        if assigned and user.role == "finance advisor":
            return True
        else:
            cls.failed += 1
            cls.log_bruteforce()
            return False
    

    @classmethod
    def get_assigned(cls, connection:Communicate, sessionId:str):
        try:
            user:User = connection.get_session_data(sessionId)["user"]
        except:
            cls.failed += 1
            cls.log_bruteforce()
            return False
        if user.role == "finance advisor":
            return True
        cls.failed += 1
        cls.log_bruteforce()
        return False


    @classmethod
    def is_admin(cls, connection:Communicate,sessionId:str):
        try:
            user:User = connection.get_session_data(sessionId)["user"]
        except:
            cls.failed += 1
            cls.log_bruteforce()
            return False
        if user.role == "admin" and user.active:
            return True
        else:
            cls.failed += 1
            cls.log_bruteforce()
            return False


def logout(connection:Communicate, sessionId:str):
    try:
        user:User = connection.get_session_data(sessionId)["user"]
        connection.end_session(sessionId)
        connection.send("succ", [])
        INFO_LOGGER.info(f"{user.username} has logged out from IP {connection.addr[0]}")
        return True
    except:
        connection.send("fail", [])
        return False


def verify_TOTP(username, totp):
    try:
        secret = AUTH_DATA_BASE.get_user_secret(username)
    except:
        return(False)
    TotpVerfier = TOTP(secret, interval=30, digits=8, digest=hashlib.sha256)
    if USER_LOCKOUT.is_locked(username):
        USER_LOCKOUT.record_attempt(username)
        return False
    if not TotpVerfier.at(dTime.now()) == totp:
        return False
    return True


def login(connection:Communicate, username:bytes, password:bytes, totp:bytes):
    try:
        username = username.decode("utf-8")#converts bytes to string
        password = password.decode("utf-8")
        totp = totp.decode("utf-8")
    except Exception as e:
        connection.send("fail", ["Invalid data"])#send response to client
        return(False)
    ip = connection.addr[0]#ip address of request
    if IP_LOCKOUT.is_locked(ip):#check if the ip is locked out
        connection.send("fail", ["User locked out"])#send response to client
        return False
    if USER_LOCKOUT.is_locked(username):#check if account is locked out
        connection.send("fail", ["User locked out"])#send response to client
        return False
    if not check_pass(username, password):#check pass fails if hashes dont match user doesnt exist or is deativated
        USER_LOCKOUT.record_attempt(username)#record attempt
        IP_LOCKOUT.record_attempt(ip)
        sleep(randint(1,3)/20)#mitigate timing attacks
        connection.send("fail", ["Username, password or totp incorrect"])
        return False
    INFO_LOGGER.info(f"User {username} from {ip} passed first authentication step.")
    success = verify_TOTP(username, totp)#check provided TOTP with expected
    if not success:
        IP_LOCKOUT.record_attempt(ip)
        USER_LOCKOUT.record_attempt(username)
        connection.send("fail", ["Username, password or totp incorrect"])
        return False
    INFO_LOGGER.info(f"User {username} from {ip} passed second authentication step.")
    id = connection.new_session_id(username)
    if id == False:#if an error occurs when creating session token
        connection.send("fail", ["An error occured please contact administration if this persists"])
        return False
    user = AUTH_DATA_BASE.get_user(username)
    user = vars(user)
    user.pop("active")
    user.pop("code")
    user.pop("signKey")
    connection.send("succ", [id, json.dumps(user)])#if sign in successfull sends sessionId and user details
    return True


def sign_up(connection:Communicate,username:str, password:str, comKey:bytes, sigKey:bytes):
    if IP_LOCKOUT.is_locked(connection.addr[0]):
        connection.send("fail", ["Invalid username or password"])
        return False
    if username == None or password == None:
        connection.send("fail", ["Invalid username or password"])
        return False
    if len(username)  < 6:
        connection.send("fail", ["Username must exceed 6 characters"])
        return False
    try:
        AUTH_DATA_BASE.create_customer(username, new_password(password), comKey, sigKey )#adds the customer to the data base
        TotpSecret = new_TOTP(username)#generates a new TOTP secret and assigns it to the customer in the database
    except Exception as e:
        connection.send("fail", ["User taken select different username"])
        IP_LOCKOUT.record_attempt(connection.addr[0])
        return False
    connection.send("totp", [TotpSecret])
    INFO_LOGGER.info(f"User {username} has been signed up from {connection.addr[0]}")
    return True




def employee_sign_up(connection:Communicate, code, username, password, comKey:bytes, sigKey:bytes):
    codeHash  = AUTH_DATA_BASE.check_code(username)
    check = check_code(code, codeHash)
    if IP_LOCKOUT.is_locked(connection.addr[0]):
        connection.send("fail", ["Invalid code or username please contact admin if you believe the code to be correct"])
        return False
    if not check:
        connection.send("fail", ["Invalid code or username please contact admin if you believe the code to be correct"])
        IP_LOCKOUT.record_attempt(connection.addr[0])
        return False
    try:
        AUTH_DATA_BASE.sign_up_employee(username,comKey,sigKey, new_password(password))
        TotpSecret = new_TOTP(username)
    except Exception as e:
        connection.send("fail", ["Error occured please contact an admin"])
        return False
    connection.send("totp", [TotpSecret])
    INFO_LOGGER.info(f"Employee {username} has signed up from {connection.addr[0]}")
    return True


def add_employee(connection:Communicate, username, sessionId, role="financial advisor"):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", ["forbidden"])
        return False
    try:
        code, codeHash = create_code()
        AUTH_DATA_BASE.create_employee_code(username,role, codeHash)
        connection.send("succ", [code])
        user = connection.get_session_data(sessionId)["user"].username
        INFO_LOGGER.info(f"Admin {user} has created employee {username} from {connection.addr[0]}")
        return True
    except Exception as e:
        connection.send("fail", ["User taken select different username"])
        return False


def transaction(connection:Communicate, account, stock, amount, action, sessionId, signature, transactionId):
    try:
        account = account.decode("utf-8")
        stock = stock.decode("utf-8")
        amount = amount.decode("utf-8")
        action = action.decode("utf-8")
        sessionId = sessionId.decode("utf-8")
        transactionId = transactionId.decode("utf-8")
    except:
        INFO_LOGGER.info(f"Recieved transaction request with unexpected encoding from {connection.addr[0]}")
        connection.send("fail", [f"Invalid data"])
        return False
    if not RBAC.transaction(connection, sessionId, account):
        ALERT_LOGGER.warn("Recieved ")
        connection.send("fail", ["Forbidden Try Logging In"])
        return False
    try:
        user = connection.get_session_data(sessionId)["user"]
        sigKey = user.signKey
        signedData = account + stock + amount + action + str(user.id) + transactionId
        if not verify_signature(signature, sigKey, signedData):
            connection.send("fail", [f"Invalid data"])
            return False
        if not AUTH_DATA_BASE.add_transaction(account, user.id, stock, amount, action, signature, transactionId):
            connection.send("fail", [f"Invalid data"])
            return False
        translation = {'s':'sold', 'b':'bought'}[action]
        connection.send("succ", [f"Stock {translation}"])
        INFO_LOGGER.info(f"User {user.username} {translation} stocks from {connection.addr[0]} for user account ID {account}")
        return True
    except:
        connection.send("fail", [f"Please Log In"])
        return(False)

    
def get_stocks(connection:Communicate, sessioId:str):
    if not connection.get_session_data(sessioId):
        connection.send("fail", ["Please Log In"])
    else:
        stocks = AUTH_DATA_BASE.get_stocks()
        if stocks:
            stockList = []
            for stock in stocks: stockList.append(json.dumps(stock))
            connection.send("stok", stockList)
        else:
            connection.send("fail", ["An error occured"])


def get_history(connection:Communicate, sessionId:str, account:int):
    if not connection.get_session_data(sessionId):
        connection.send("fail", ["Please Log In"])
        return
    if not RBAC.transaction(connection, sessionId, account):
        connection.send("fail", ["Forbidden"])
        return False
    history = AUTH_DATA_BASE.get_history(account)
    if history:
        historyList = []
        for item in history:
            historyList.append(json.dumps(item))
        connection.send("succ", historyList)
        username = connection.get_session_data(sessionId)["user"].username
        INFO_LOGGER.info(f"User {username} retrieved user with ID {account}'s history from {connection.addr[0]}")
        return
    connection.send("fail", ["Failed to retrieve history"])
    return


def get_messages(connection:Communicate, sessionId, recipientId=None):
    if not connection.get_session_data(sessionId):
        connection.send("fail", ["Please Log In"])
        return
    user:User = connection.get_session_data(sessionId)["user"]#get user info from session
    userId = user.id
    if user.role == "customer":
        recipientId = AUTH_DATA_BASE.get_assigned_employee(userId)
        if not recipientId:
            connection.send("fail", [b"None"])
            return False
    if recipientId == None:
        connection.send("fail", [b"Couldnt Find Recipient"])
        return False
    if not RBAC.get_message(connection, sessionId, recipientId):#check user has permission to message
        connection.send("fail", [b"Forbidden"])
        return False
    try:
        pub = AUTH_DATA_BASE.get_public_key(recipientId)
        messages = AUTH_DATA_BASE.get_messages(userId, recipientId)
    except:
        connection.send("fail", [b"None"])
        return
    INFO_LOGGER.info(f"User {user.username} retrieved messages from {connection.addr[0]}")
    connection.send("succ", [pub, json.dumps(messages)])


def get_users(connection:Communicate, sessionId):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", [])
        return False
    users = AUTH_DATA_BASE.get_user_list()
    userList = []
    for user in users:
        userList.append(json.dumps(user))
    connection.send("succ", userList)
    user:User = connection.get_session_data(sessionId)["user"]
    INFO_LOGGER.info(f"Admin {user.username} retrieved user list from {connection.addr[0]}")


def assign_employee_to_customer(connection:Communicate, employeeId:int, customerId:int, sessionId:str):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", [])
        return False
    employee:User = AUTH_DATA_BASE.get_user_from_id(employeeId)
    customer:User = AUTH_DATA_BASE.get_user_from_id(customerId)
    if employee.role == "finance advisor" and customer.role == "customer" and employee.active and customer.active:
        confirm = AUTH_DATA_BASE.assign_to_employee(customerId, employeeId)
        if confirm:
            connection.send("succ", [])
            user:User = connection.get_session_data(sessionId)["user"]
            INFO_LOGGER.info(f"Admin {user.username} assigned customer {customer.username} to {employee.username} from {connection.addr[0]}")
            return True
        connection.send("fail", ["customer already assigned to employee"])
        return False
        
    else:
        connection.send("fail", ["Users are not a finance advisor and customer or are not active"])
        return False


def send_msg(connection:Communicate, message, sessionId, recipientId=None):
    if not connection.get_session_data(sessionId):
        connection.send("fail", ["Please Log In"])
        return False
    user:User = connection.get_session_data(sessionId)["user"]#get user info from session
    userId = user.id
    if user.role == "customer":
        recipientId = AUTH_DATA_BASE.get_assigned_employee(userId)
        if not recipientId:
            connection.send("fail", [b"None"])
            return False
    if not RBAC.get_message(connection, sessionId, recipientId):#check user has permission to message
        connection.send("fail", [b"Forbidden"])
        return False
    if recipientId == None:
        connection.send("fail", [b"Couldnt Find Recipient"])
        return False
    AUTH_DATA_BASE.add_message(userId, recipientId, str(message)[2:-1])
    connection.send("succ", ["message added"])
    INFO_LOGGER.info(f"User {user.username} sent message from {connection.addr[0]}")
    return True


def get_assigned(connection:Communicate, sessionId):
    if not RBAC.get_assigned(connection, sessionId):
        connection.send("fail", ["forbiden"])
        return False
    user:User = connection.get_session_data(sessionId)["user"]
    assignedCustomers = AUTH_DATA_BASE.get_customers_assigned_to_employee(user.id)
    customerList = []
    if assignedCustomers:
        for customer in assignedCustomers:
            customerList.append(json.dumps(customer))
        connection.send("succ", customerList)
        user:User = connection.get_session_data(sessionId)["user"]
        INFO_LOGGER.info(f"Employee {user.username} retrieved their assigned users from {connection.addr[0]}")
        return True
    connection.send("fail", ["no customers assigned to you"])
    return False

def deactivate(connection:Communicate, userId:int, sessionId:str):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", ["forbidden"])
        return False
    user = connection.get_session_data(sessionId)["user"]
    if int(user.id) == userId:
        connection.send("fail", ["Can't deactivate yourself"])
        return False
    result = AUTH_DATA_BASE.deactivate_user(userId)
    if result:
        connection.close_user_sessions(userId)
        connection.send("succ",[])
        INFO_LOGGER.info(f"Admin {user.username} deactivated user with ID {userId} from {connection.addr[0]}")
        return True
    else:
        connection.send("fail",[])
        return False


def activate(connection:Communicate, userId:int, sessionId:str):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", ["forbidden"])
        return False
    user = connection.get_session_data(sessionId)["user"]
    if int(user.id) == userId:
        connection.send("fail", ["Can't activate yourself"])
        return False
    result = AUTH_DATA_BASE.activate_user(userId)
    if result:
        connection.send("succ",[])
        INFO_LOGGER.info(f"Admin {user.username} activated user with ID {userId} from {connection.addr[0]}")
        return True
    else:
        connection.send("fail",[])
        return False


def revoke_key(connection:Communicate, sessionId:str, type:str, target:str=None):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", ["forbidden"])
        return False
    user:User = connection.get_session_data(sessionId)["user"]
    if type == "data":
        AUTH_DATA_BASE.revoke_key()
        connection.send("succ", ["Key revoked database rekeyed"])
        INFO_LOGGER.info(f"Admin {user.username} revoked and rekeyed data base from {connection.addr[0]}")
        return True
    if type == "sign" and target != None:
        AUTH_DATA_BASE.revoke_users_sign_key(int(target))
        connection.send("succ", ["Sign key has been revoked"])
        INFO_LOGGER.info(f"Admin {user.username} revoked user with ID {target} public signing key from {connection.addr[0]}")
        return True
    if type == "com" and target != None:
        AUTH_DATA_BASE.revoke_users_com_key(int(target))
        connection.send("succ", ["Comunication key revoked"])
        INFO_LOGGER.info(f"Admin {user.username} revoked user with ID {target} public communication key from {connection.addr[0]}")
        return True
    connection.send("fail", ["invalid option"])
    return False

def backup(connection:Communicate, sessionId:str):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", ["forbidden"])
        return False
    newKey = urandom(32)
    AUTH_DATA_BASE.backup_rekey_database(newKey)
    connection.send("succ", ["Database backed up"])
    user:User = connection.get_session_data(sessionId)["user"]
    INFO_LOGGER.info(f"Admin {user.username} backed up and rekeyed database from {connection.addr[0]}")
    return True

def set_key(connection:Communicate, sessionId:str, type:str, target:str, key:bytes):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", ["forbidden"])
        return False
    if type == "sign":
        AUTH_DATA_BASE.revoke_users_sign_key(int(target), key)
        connection.send("succ", ["Sign key has been revoked"])
        user:User = connection.get_session_data(sessionId)["user"]
        INFO_LOGGER.info(f"Admin {user.username} set user with ID {target} signing publickey from {connection.addr[0]}")
        return True
    if type == "com":
        AUTH_DATA_BASE.revoke_users_com_key(int(target), key)
        connection.send("succ", ["Comunication key revoked"])
        user:User = connection.get_session_data(sessionId)["user"]
        INFO_LOGGER.info(f"Admin {user.username} set user with ID {target} communication publickey from {connection.addr[0]}")
        return True
    connection.send("fail", ["invalid option"])
    return False


def get_logs(connection:Communicate, sessionId):
    if not RBAC.is_admin(connection, sessionId):
        connection.send("fail", ["forbidden"])
        return False
    try:
        f = open("Info.log", "r")
        infoLog = []
        for line in f:
            infoLog.append(line)
        f.close()
        connection.send("succ", infoLog)
        user:User = connection.get_session_data(sessionId)["user"]
        INFO_LOGGER.info(f"Admin {user.username} accessed info log from {connection.addr[0]}")
        f = open("Security_Alert.log", "r")
        secLog = []
        for line in f:
            secLog.append(line)
        f.close()
        connection.send("succ", secLog)
        INFO_LOGGER.info(f"Admin {user.username} accessed warning log from {connection.addr[0]}")
    except:
        connection.send("fail", ["Error getting logs"])
        return False
    return True
    

code, codeHash = create_code()
print(code)
AUTH_DATA_BASE.remove_test_user("devAdmin")
res = AUTH_DATA_BASE.create_employee_code("devAdmin","admin", codeHash)
print(res)





