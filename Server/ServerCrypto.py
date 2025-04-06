import argon2
from datetime import datetime as dTime
from datetime import timedelta
import logging
import sqlite3
from os import urandom
import pyotp
import hashlib
import base64
import qrcode
import tkinter
from communicate import Communicate







logging.basicConfig(format='%(asctime)s %(message)s')
IPLOCKOUT_ATTEMPTS = 30
ALERT_LOGGER = logging.getLogger("Security_Alert")
ALERT_LOGGER.setLevel(logging.WARNING)
ALERT_LOGGER.propagate = False
ALERT_LOGGER.addHandler(logging.FileHandler("Security_Alert.log"))
AUTH_DATA_BASE = sqlite3.connect("Authenticate.db")


class IpUserLockoutManager:
    IpUserLock = {}
    def __init__(self, attempts=3, lockoutTime=timedelta(minutes=3)):
        self.attempts = attempts
        self.lockoutTime = lockoutTime
        self.IpUserLockList = LinkedList()

    def record_attempt(self, ip, user):
        userIp = str(ip) + str(user)
        time = dTime.now()
        if userIp not in self.IpUserLock:
            new_node = self.IpUserLockList.add(userIp, time)
            self.IpUserLock[userIp] = new_node
        else:
            self.IpUserLock[userIp].time = time
            self.IpUserLock[userIp].attempts += 1
            self.IpUserLockList.to_top(self.IpUserLock[userIp])
        return
    
    def is_locked(self, ip, user):
        userIp = str(ip) + str(user)
        if userIp not in self.IpUserLock:
            return False
        else:
            if dTime.now() - self.IpUserLock[userIp].time < self.lockoutTime and self.IpUserLock[userIp].attempts >= self.attempts:
                if self.IpUserLock[userIp].attempts == self.attempts:
                    ALERT_LOGGER.warning(f"IP {ip} has been locked out of {user} account after {self.attempts} failed attempts.")
                return True
            elif dTime.now() - self.IpUserLock[userIp].time >= self.lockoutTime:
                self.IpUserLockList.remove(self.IpUserLock[userIp])
                self.IpUserLock.pop(userIp)
                return False
            else:
                return False




class IpLockoutManager:
    IpLock = {}

    def __init__(self, attempts=30, lockoutTime=timedelta(minutes=20)):
        self.attempts = attempts
        self.lockoutTime = lockoutTime
        self.IpLockList = LinkedList()

    def record_attempt(self, ip):
        time = dTime.now()
        if ip not in self.IpLock:
            new_node = self.IpLockList.add(ip, time)
            self.IpLock[ip] = new_node
        else:
            self.IpLock[ip].time = time
            self.IpLock[ip].attempts += 1
            self.IpLockList.to_top(self.IpLock[ip])
        return

    def is_locked(self, ip):
        if ip not in self.IpLock:
            return False
        else:
            if dTime.now() - self.IpLock[ip].time < self.lockoutTime and self.IpLock[ip].attempts >= self.attempts:
                if self.IpUserLock[ip].attempts == self.attempts:
                    ALERT_LOGGER.warning(f"IP {ip} has been locked out of all account after {self.attempts} failed attempts.")
                return True
            elif dTime.now() - self.IpLock[ip].time >= self.lockoutTime:
                self.IpLockList.remove(self.IpLock[ip])
                self.IpLock.pop(ip)
                return False
            else:
                return False


class LinkedList:
    def __init__(self, lockoutTime, cleanUpLimit=5000):
        self.head = None
        self.tail = None
        self.count = 0
        self.cleanUpLimit = cleanUpLimit
        self.lastCleaned = dTime.now()
        self.timeBetweenCleanUp = timedelta(minutes=5)
        self.lastLogged = None
        self.lockoutTime = lockoutTime

    def add(self, value, time):
        new_node = LinkedNode(value, time)
        new_node.next = self.head
        self.count += 1
        if self.count > self.cleanUpLimit and dTime.now() - self.lastCleaned > self.timeBetweenCleanUp:
            self.cleanUp()
        elif self.count > self.cleanUpLimit:
            if self.lastLogged == None:
                self.lastLogged = dTime.now()
                ALERT_LOGGER.warning(f"IP Lock List has exceeded {self.cleanUpLimit} items in short period of time possible Brute Force.")
        if self.head != None:
            self.head.prev = new_node
        self.head = new_node
        return new_node
    
    def remove(self, node):
        if node == None:
            return
        if node.prev:
            node.prev.next = node.next
        if node.next:
            node.next.prev = node.prev
        if node == self.head:
            self.head = node.next
        if node == self.tail:
            self.tail = node.prev
        del node
        self.count -= 1
        return
    
    def to_top(self, node):
        if node == self.head:
            return
        if node.prev != None:
            node.prev.next = node.next
        if node.next != None:
            node.next.prev = node.prev
        node.next = self.head
        self.head.prev = node
        self.head = node
        return

    """ def cleanUp(self, ):
        node = self.tail
        while node.time - dTime.now() > self.lockoutTime:
            node = node.prev
            del node.next
            
            self.remove(node.next)
        while 
 """


class LinkedNode:
    def __init__(self, value, time):
        self.value = value
        self.time = time
        self.next = None
        self.prev = None
        self.attempts = 1



def new_TOTP(username):
    if username == None:
        return False
    user = AUTH_DATA_BASE.execute("SELECT username, secret FROM Users WHERE username = ?", [username]).fetchall()
    if len(user) != 1 or user[0][1] != None:
        return False
    secret = urandom(32)
    secret = base64.b32encode(secret)
    AUTH_DATA_BASE.execute("Update Users set secret=? where username=?",  [secret, username])
    AUTH_DATA_BASE.commit()
    return(secret.decode("utf-8"))
    


def verify_TOTP(username, code):
    return




def sign_up(username, password):
    if username == None or password == None:
        return False
    try:
        AUTH_DATA_BASE.execute('INSERT INTO Users (username, password) VALUES (?, ?)',
                             (username, bytes(new_password(password), "utf-8")))
        AUTH_DATA_BASE.commit()
        TotpSecret = new_TOTP(username)
        Communicate.send("totp", [TotpSecret])
    except Exception as e:
        print(e.args[0])
        return False
    return True



def new_password(clientPassHash):
    hasher = argon2.PasswordHasher()
    hashedPassword = hasher.hash(clientPassHash)
    return(hashedPassword)


def get_pass (username):

    return(new_password("ynjlzm8Alyh+EGIB6UbIUcexDSasAf+QuiOutlGm5XfvXusgU9ue7mQDPHxGmB7cUyaQIiAOhn1Ihs6EFV9c0g"))


def check_pass(username, password):
    currentPass = get_pass(username)
    return(argon2.PasswordHasher().verify(bytes(currentPass, "utf-8"), bytes(password, "utf-8")))








