from datetime import datetime as dTime, timedelta
from log import ALERT_LOGGER, INFO_LOGGER






class UserLockoutManager:
    def __init__(self, attempts=3, lockoutTime=timedelta(minutes=5)):
        self.attempts = attempts
        self.lockoutTime = lockoutTime
        self.UserLockList = LinkedList(lockoutTime)
        self.UserLock = {}

    def record_attempt(self, username):
        time = dTime.now()
        if username not in self.UserLock:
            new_node = self.UserLockList.add(username, time)
            self.UserLock[username] = new_node
        elif dTime.now() - self.UserLock[username].time >= self.lockoutTime:
            self.UserLockList.remove(self.UserLock[username])
            self.UserLock.pop(username)
            self.record_attempt(username)
        else:
            self.UserLock[username].time = time
            self.UserLock[username].attempts += 1
            if self.UserLock[username].attempts == self.attempts:
                ALERT_LOGGER.warn(f"User {username} has been locked out after {self.attempts} failed attempts.")
            self.UserLockList.to_top(self.UserLock[username])
        return

    def is_locked(self, username):
        if username not in self.UserLock:
            return False
        else:
            if dTime.now() - self.UserLock[username].time < self.lockoutTime and self.UserLock[username].attempts >= self.attempts:
                return True
            elif dTime.now() - self.UserLock[username].time >= self.lockoutTime:
                self.UserLockList.remove(self.UserLock[username])
                self.UserLock.pop(username)
                return False
            else:
                return False




class IpLockoutManager:
    def __init__(self, attempts=30, lockoutTime=timedelta(minutes=20)):
        self.attempts = attempts
        self.lockoutTime = lockoutTime
        self.IpLockList = LinkedList(lockoutTime)
        self.IpLock = {}

    def record_attempt(self, ip):
        time = dTime.now()
        if ip not in self.IpLock:
            new_node = self.IpLockList.add(ip, time)
            self.IpLock[ip] = new_node
        elif dTime.now() - self.IpLock[ip].time >= self.lockoutTime:
            self.IpLockList.remove(self.IpLock[ip])
            self.IpLock.pop(ip)
            self.record_attempt(ip)
        else:
            self.IpLock[ip].time = time
            self.IpLock[ip].attempts += 1
            if self.IpLock[ip].attempts == self.attempts:
                ALERT_LOGGER.warn(f"IP {ip} has been locked out of all account after {self.attempts} failed attempts.")
            self.IpLockList.to_top(self.IpLock[ip])
        return

    def is_locked(self, ip):
        if ip not in self.IpLock:
            return False
        else:
            if dTime.now() - self.IpLock[ip].time < self.lockoutTime and self.IpLock[ip].attempts >= self.attempts:
                return True
            elif dTime.now() - self.IpLock[ip].time >= self.lockoutTime:
                self.IpLockList.remove(self.IpLock[ip])
                self.IpLock.pop(ip)
                return False
            else:
                return False


class LinkedList:
    def __init__(self, lockoutTime, cleanUpLimit=2000):
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
                ALERT_LOGGER.warn(f"IP Lock List has exceeded {self.cleanUpLimit} items in short period of time possible Brute Force.")
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





IP_LOCKOUT = IpLockoutManager()
USER_LOCKOUT = UserLockoutManager()
