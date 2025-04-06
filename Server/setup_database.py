import sqlite3
from os import urandom
import pyotp
import hashlib
import base64
import qrcode
from time import sleep
import datetime as dat
import tkinter
from PIL import Image, ImageTk

AUTH_DATA_BASE = sqlite3.connect("Server/Authenticate.db")

AUTH_DATA_BASE.execute('CREATE TABLE IF NOT EXISTS Users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password byte NOT NULL, secret byte)')

try:
    AUTH_DATA_BASE.execute('INSERT INTO Users (username, password) VALUES (?, ?)',
                     ('test_user', b'hashed_password'))
except Exception as e:
    print(e.args[0])

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
    






code = new_TOTP("test_user")
user = AUTH_DATA_BASE.execute("SELECT username, secret FROM Users WHERE username = ?", ["test_user"]).fetchall()
print(user)
secret = user[0][1]
totp = pyotp.TOTP(secret.decode("utf-8"), interval=30, digits=8, digest=hashlib.sha256)
while True:
    print(totp.at(dat.datetime.now()+dat.timedelta(seconds=10)))
    print(totp.verify(input("Enter TOTP: ")))
