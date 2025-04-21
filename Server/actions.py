
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
from ServerCrypto import new_password, new_TOTP, verify_signature
import string
from random import choice
import json



class RBAC:



    @classmethod
    def transaction(cls, connection:Communicate,sessionId:str, account:str):
        try:
            user:User = connection.get_session_data(sessionId)["user"]
            assigned = AUTH_DATA_BASE.assigned_to_employee(user.id, account)
        except:
            return False
        if not user.active:
            return user.active
        if int(account) == user.id:
            return True
        if assigned and user.role == "finance advisor":
            return True
        else:
            return False




def verify_TOTP(username, totp):
    try:
        secret = AUTH_DATA_BASE.get_user_secret(username).decode("utf-8")
    except:
        return(False)
    TotpVerfier = TOTP(secret, interval=30, digits=8, digest=hashlib.sha256)
    if USER_LOCKOUT.is_locked(username):
        USER_LOCKOUT.record_attempt(username)
        return False
    print(TotpVerfier.at(dTime.now()+timedelta(seconds=10)))
    if not TotpVerfier.at(dTime.now()+timedelta(seconds=10)) == totp:
        USER_LOCKOUT.record_attempt(username)
        return False
    return True

def login(connection:Communicate, username:bytes, password:bytes, totp:bytes):
    try:
        username = username.decode("utf-8")
        password = password.decode("utf-8")
        totp = totp.decode("utf-8")
    except Exception as e:
        print(e)
        connection.send("fail", ["Invalid data"])
        return(False)
    ip = connection.addr[0]
    if username == None or password == None or totp == None:
        connection.send("fail", ["Username, password or totp incorrect"])
        return False
    if IP_USER_LOCKOUT.is_locked(ip, username):
        IP_USER_LOCKOUT.record_attempt(ip, username)
        IP_LOCKOUT.record_attempt(ip)
        connection.send("fail", ["User locked out"])
        return False
    if IP_LOCKOUT.is_locked(ip):
        IP_USER_LOCKOUT.record_attempt(ip, username)
        IP_LOCKOUT.record_attempt(ip)
        connection.send("fail", ["User locked out"])
        return False
    if USER_LOCKOUT.is_locked(username):
        connection.send("fail", ["User locked out"])
        return False
    try:
        AUTH_DATA_BASE.get_user_password(username)
    except:
        sleep(randint(1, 5)/20)
        IP_LOCKOUT.record_attempt(ip)
        connection.send("fail", ["Username, password or totp incorrect"])
        return False
    isActive =  AUTH_DATA_BASE.get_user(username).active
    if not isActive:
        IP_LOCKOUT.record_attempt(ip)
        connection.send("fail", ["Account deactivated please contact administrator if you believe this is a mistake"])
        return False
    if not check_pass(username, password):
        IP_USER_LOCKOUT.record_attempt(ip, username)
        IP_LOCKOUT.record_attempt(ip)
        sleep(randint(1, 5)/20)
        connection.send("fail", ["Username, password or totp incorrect"])
        return False
    INFO_LOGGER.info(f"User {username} from {ip} passed first authentication step.")
    success = verify_TOTP(username, totp)
    if not success:
        USER_LOCKOUT.record_attempt(username)
        connection.send("fail", ["Username, password or totp incorrect"])
        return False
    INFO_LOGGER.info(f"User {username} from {ip} passed second authentication step.")
    id = connection.new_session_id(username)
    if id ==False:
        connection.send("fail", ["An error occured please contact administration if this persists"])
        return False
    user = AUTH_DATA_BASE.get_user(username)
    user = vars(user)
    user.pop("active")
    user.pop("code")
    user.pop("signKey")
    connection.send("succ", [id, json.dumps(user)])
    return True




def sign_up(connection:Communicate,username:str, password:str, comKey:bytes, sigKey:bytes):
    if username == None or password == None:
        connection.send("fail", ["Invalid username or password"])
    if len(username)  < 6:
        connection.send("fail", ["Username must exceed 6 characters"])
    try:
        AUTH_DATA_BASE.create_customer(username, new_password(password), comKey, sigKey )
        TotpSecret = new_TOTP(username)
    except Exception as e:
        connection.send("fail", ["User taken select different username"])
        IP_LOCKOUT.record_attempt(connection.addr[0])
        return False
    connection.send("totp", [TotpSecret])
    return True



def employee_sign_up(connection:Communicate, code, username, password):
    check  = AUTH_DATA_BASE.check_code(code, username)
    if not check:
        connection.send("fail", ["Invalid code or username please contact admin if you believe the code to be correct"])
        return False
    else:
        return sign_up(connection, username, password)




def add_employee(connection, username):
    try:
        code = AUTH_DATA_BASE.add_employee(username)
        connection.send("succ", [code])
    except Exception as e:
        connection.send("fail", ["User taken select different username"])
        IP_LOCKOUT.record_attempt(connection.addr[0])
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
            historyList.append(json.dumps(item[:-1]))
        connection.send("hist", historyList)
        return
    connection.send("fail", ["Failed to retrieve history"])
    return



def get_messages(connection:Communicate, sessionId):
    if not connection.get_session_data(sessionId):
        connection.send("fail", ["Please Log In"])
        return
    user:User = connection.get_session_data(sessionId)["user"]#get user info from session
    if not user.active:
        connection.send("fail", ["User account not active"])
        return
    userId = user.id
    try:
        pub = AUTH_DATA_BASE.get_sender_public_key(userId)
        messages = AUTH_DATA_BASE.get_messages(userId)
    except:
        connection.send("Fail", [b"None"])
        return
    connection.send("succ", [pub]+messages)