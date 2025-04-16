
from time import sleep
from random import randint
from ServerCrypto import check_pass
from Lockout import IP_LOCKOUT, IP_USER_LOCKOUT, USER_LOCKOUT
from database import AUTH_DATA_BASE
from log import INFO_LOGGER, ALERT_LOGGER
import hashlib
from pyotp import TOTP
from datetime import datetime as dTime, timedelta
from communicate import Communicate
from ServerCrypto import new_password, new_TOTP
import string

string.printable
def verify_TOTP(username, totp):
    try:
        secret = AUTH_DATA_BASE.get_user_secret(username).decode("utf-8")
    except:
        return(False)
    TotpVerfier = TOTP(secret, interval=30, digits=8, digest=hashlib.sha256)
    if USER_LOCKOUT.is_locked(username):
        USER_LOCKOUT.record_attempt(username)
        return False
    if not TotpVerfier.at(dTime.now()+timedelta(seconds=10)) == totp:
        USER_LOCKOUT.record_attempt(username)
        return False
    return True

def login(connection:Communicate, username, password, totp):
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
        user = AUTH_DATA_BASE.get_user_password(username)
    except:
        sleep(randint(1, 5)/20)
        connection.send("fail", ["Username, password or totp incorrect"])
        return False
    if user == None:
        IP_LOCKOUT.record_attempt(ip)
        connection.send("fail", ["User locked out"])
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
        connection.send("fail", ["username, password or totp incorrect"])
        return False
    INFO_LOGGER.info(f"User {username} from {ip} passed second authentication step.")
    id = connection.new_session_id(username)
    connection.send("succ", [id])
    return True




def sign_up(connection:Communicate,username:str, password:str):
    if username == None or password == None:
        connection.send("fail", ["Invalid username password"])
    if len(username)  < 6:
        connection.send("fail", ["Username must exceed 6 characters"])
    try:
        AUTH_DATA_BASE.create_user(username, new_password(password))
        TotpSecret = new_TOTP(username)
    except Exception as e:
        print(e.args[0])
        connection.send("fail", ["User taken select different username"])
        IP_LOCKOUT.record_attempt(connection.addr[0])
        return False
    connection.send("totp", [TotpSecret])
    return True



def employee_sign_up(connection:Communicate, code, username, password):
    check  = AUTH_DATA_BASE.check_code(code, username)
    if not check:
        connection.send("fail", ["invalid token or username please contact admin"])
        return False
    else:
        return sign_up(connection, username, password)




def add_employee(connection, username):
    try:
        AUTH_DATA_BASE.create_user(username)
        TotpSecret = new_TOTP(username)
    except Exception as e:
        print(e.args[0])
        connection.send("fail", ["User taken select different username"])
        IP_LOCKOUT.record_attempt(connection.addr[0])
        return False
