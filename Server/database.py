from pysqlcipher3 import dbapi2 as sqlite3
import os
import shutil
import datetime
from Crypto.Cipher import AES
import argon2
from log import INFO_LOGGER
import string
from random import choice

class User:
    def __init__(self, id, username, role, active, code, sign_key, date):
        self.id = id#id of the user
        self.username = username
        self.role = role#roel of the user
        self.active = (active == "y")#to determine if the account is active
        self.code = code#whether its the first time the user has logged in, used for employee accounts to prompt for new password if first time logging in
        self.signKey = sign_key#public key used to verify users signatures
        self.dateCreated = date
        



class CustomDataBase:
    def __init__(self, dbFile):
        self._dbFile = dbFile
        self._connection = sqlite3.connect(self._dbFile)
        self._cursor = self._connection.cursor()
        self.key = b'9\xfd\xe4\xad\r\xa10\xe2l\xc0\xa7 \xda\xdb\xd5ep$\xae\xfd\x0cz\xfd\xea\xde\x97\xc8M\x9f_DK'
        self.kek = b'q\x0e\xcdMF\xd2\x19w/\xf8\xca(0\x96}BN\x94\x8f\xc4;}\x83.\xb8\x88$B\xc1\xb3l['
        self._cursor.execute(f"PRAGMA key = \"x'{self.key.hex()}\"")
        self._cursor.execute("PRAGMA foreign_keys=ON")
        print(self._cursor.execute("select * from users").fetchall())
        print(self._cursor.execute("select * from transactions").fetchall())
        print(self._cursor.execute("select * from stocks").fetchall())
        """ try:#This is all for development remove this section and initial setup when in production
            self._cursor.execute("drop table Users")
        except sqlite3.OperationalError:
            pass
        try:
            self._cursor.execute("drop table Roles")
        except sqlite3.OperationalError:
            pass
        try:
            self._cursor.execute("drop table Transactions")
        except sqlite3.OperationalError:
            pass
        try:
            self._cursor.execute("drop table Employee_Customer")
        except sqlite3.OperationalError:
            pass
        try:
            self._cursor.execute("drop table messages")
        except sqlite3.OperationalError:
            pass

    
        self.initial_setup()
        self._cursor.execute(CREATE TABLE Transactions(
        trans_id INTEGER PRIMARY KEY,
        unique_id TEXT UNIQUE NOT NULL,
        user_account INTEGER NOT NULL,
        stock INTEGER NOT NULL,
        amount INTEGER NOT NULL check(amount > 0),
        time_stamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        action varchar(1) NOT NULL check(action in ('s', 'b')),
        transaction_initiator INTEGER NOT NULL,
        signature bytea NOT NULL,
        FOREIGN KEY (user_account) REFERENCES Users(user_id),
        FOREIGN KEY (transaction_initiator) REFERENCES Users(user_id),
        FOREIGN KEY (stock) REFERENCES stocks(stock_id)
        ))"""
    


    def initial_setup(self):
        self._cursor.execute("""CREATE TABLE Users (
            user_id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            code bytea,
            password bytea,
            secret bytea,
            com_key bytea,
            sign_key bytea,
            active varchar(1) NOT NULL DEFAULT 'n',
            role TEXT default "customer",
            account_created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")
        self._cursor.execute("""CREATE TABLE Employee_Customer (
            pair_id INTEGER PRIMARY KEY,
            employee INTEGER NOT NULL,
            customer INTEGER NOT NULL,
            FOREIGN KEY (employee) REFERENCES Users(user_id),
            FOREIGN KEY (customer) REFERENCES Users(user_id)
            )""")
        
        self._cursor.execute("""create table stocks(
            stock_id INTEGER PRIMARY KEY,
            price REAL NOT NULL DEFAULT 10.00,
            name TEXT NOT NULL UNIQUE                
            )
            """)
        
        self._cursor.execute("""CREATE OR REPLACE TABLE Transactions(
            trans_id INTEGER PRIMARY KEY,
            user_account INTEGER NOT NULL,
            stock INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            time_stamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            action varchar(1) NOT NULL,
            transaction_initiator INTEGER NOT NULL,
            signature bytea NOT NULL,
            FOREIGN KEY (user_account) REFERENCES Users(user_id),
            FOREIGN KEY (transaction_initiator) REFERENCES Users(user_id)
            FOREIGN KEY (stock) REFERENCES stock(stock_id)
            )""")
        self._cursor.execute("""create table messages(
            message_id INTEGERR PRIMARY KEY,
            sender INTEGER NOT NULL,
            recipient INTEGER NOT NULL,
            time_stamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            message bytea NOT NULL,
            FOREIGN KEY (sender) REFERENCES Users(user_id),
            FOREIGN KEY (recipient) REFERENCES Users(user_id)               
            )
            """)


    def get_user_password(self, username):
        result = self._cursor.execute("SELECT password, active FROM Users WHERE username = ?", [username]).fetchone()
        print(result)
        if result == None:
            raise Exception("User does not exist")
        if result[0] == None:
            raise Exception("User has no password")#raise exception to stop users without passwords from logging on
        if result[1] != "y":#throws error if account is deactivated stops sign in on deactivated accounts
            raise Exception("User has no password")
        if result:
            return result[0]
        return None


    def get_user_secret(self, username):
        result = self._cursor.execute("SELECT secret FROM Users WHERE username = ?", [username]).fetchone()
        if result == None:
            raise Exception("User does not exist")
        if result[0] == None:
            raise Exception("Secret does not exist")
        return result[0]


    def create_customer(self, username, password, comKey, sigKey):
        try:
            self._cursor.execute('INSERT INTO Users (username, password, com_key, sign_key, active, role) VALUES (?, ?, ?, ?, ?, ?)',
                                (username, bytes(password, "utf-8"), comKey, sigKey, "y", "customer"))
            self._connection.commit()
            return
        except Exception as e:
            print(e)#not for production
            raise Exception("User already exists")


    def add_secret(self, username, secret):
        try:
            user = self._cursor.execute("SELECT secret FROM Users WHERE username=?", (username,))
            res = user.fetchone()
            if res == None:
                raise Exception(f"User '{username}' does not exist")
            elif res[0]: 
                raise Exception(f"User '{username}' already has a secret")
            self._cursor.execute(
                "UPDATE Users SET secret=? WHERE username=?",
                (secret, username)
            )
            self._connection.commit()
        except sqlite3.IntegrityError as e:
            raise Exception(f"Failed to update secret: for user {username}")


    def encrypt_key(self, key, kek=b"this is a 32 byte key to test re"):
        iv = os.urandom(16)
        cipher = AES.new(kek, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(key)
        return iv + ciphertext


    def rekey_database(self, new_key: bytes, db_path="Authenticate.db"):
        date = datetime.datetime.now().date()
        backup_name = f".\\backup\\Authenticate_backup_{date}.db"
        shutil.copy2(db_path, backup_name)
        print(f"Database backed up to: {backup_name}")
        encrypted_key = self.encrypt_key(self.key, self.kek)
        key_file = f".\\backup\\key_{date}.bin"
        with open(key_file, "wb") as f:
            f.write(encrypted_key)
        print(f"Encrypted old key saved to: {key_file}")
        self.key = new_key
        self._cursor.execute(f"PRAGMA rekey = \"x'{new_key.hex()}\"")
        self._connection.commit()
        print("Database rekeyed successfully.")
    
    
    def get_user(self, username):
        user = self._cursor.execute("select user_id, username, role, active, code, sign_key, account_created from users where username = ?", (username,)).fetchone()
        if user == None:
            raise ValueError("user does not exist")
        return User(user[0], user[1], user[2], user[3], user[4], user[5], user[6])

    def get_user_from_id(self, userId):
        user = self._cursor.execute("select user_id, username, role, active, code, sign_key, account_created from users where user_id = ?", (userId,)).fetchone()
        if user == None:
            raise ValueError("user does not exist")
        return User(user[0], user[1], user[2], user[3], user[4], user[5], user[6])


    def add_transaction(self, user_id, isuer_id, stock_id, amount, action, sig, unique_id):
        try:
            self._cursor.execute("insert into transactions (user_account,stock,amount,action,transaction_initiator,signature, unique_id) values (?,?,?,?,?,?, ?)",
                            (int(user_id), int(stock_id), int(amount), action, int(isuer_id), sig, unique_id))
            self._connection.commit()
        except:
            return False
        return True


    def assign_to_employee(self, customer_id, employee_id):
        try:
            alreadyAssigned = self._cursor.execute("select pair_id from Employee_Customer where customer = ?", (customer_id,)).fetchone()
        except:
            return False#if error orcurrs default deny
        if alreadyAssigned != None:#if user already has an employee assigned to them a different one can't be assigned untill the previous has been de-assigned
            return False
        try:
            self._cursor.execute("insert into Employee_Customer (customer, employee) values (?,?)", (customer_id, employee_id))
            self._connection.commit()
            return True
        except:
            return False


    def remove_test_user(self, username):#remove this in production code only used for the test cases
        self._cursor.execute("delete from users where username = ?", (username,))
        self._connection.commit()



    def assigned_to_employee(self, employee_id, customer_id):
        try:
            res = self._cursor.execute("select pair_id from Employee_Customer where customer = ? and employee = ?", (customer_id, employee_id)).fetchone()
            if res == None:
                return False
            return True
        except:
            return False
        
    def get_assigned_employee(self, userId:int):
        result = self._cursor.execute("select employee from employee_customer where customer = ?", (userId,)).fetchone()
        if not result:
            return False
        return result[0]
    

    def get_customers_assigned_to_employee(self, employeeId):
        customers = self._cursor.execute("select u.user_id, u.username, u.active from users u inner join Eployee_Customer e on u.user_id = e.customer where e.employee = ? and u.active = 'y' order by u.username", (employeeId,)).fetchall()
        return customers


    def get_messages(self, userId:int):
        msgs = self._cursor.execute("select sender, message from messages where sender = ? or recipient = ?", (userId, userId)).fetchall()
        return(msgs)
    
    def get_sender_public_key(self, userId):
        employeeId = self.get_assigned_employee(userId)
        publicKey = self._cursor.execute("select com_key from Users where user_id = ?", (employeeId,)).fetchone()[0]
        return publicKey
        

    def get_stocks(self):
        try:
            stocks = self._cursor.execute("select * from stocks").fetchall()
            return stocks
        except:
            return None
    
    def get_history(self,account):
        try:
            history = self._cursor.execute("select * from Transactions where user_account = ?", (account,)).fetchall()
            print(history)
            return history
        except:
            return None
        


    def deactivate_user(self,username):
        self._cursor.execute("update Users set active = 'n' where username = ?", (username,))
        self._connection.commit()
        return
    
    def activate_user(self, username):
        self._cursor.execute("update Users set active = 'y' where username = ?", (username,))
        self._connection.commit()
        return

    def add_stock(self, name, price):
        self._cursor.execute("insert into stocks (name, price) values (?,?)", (name,price))
        self._connection.commit()
        return



    def check_code(self, username):
        user = self._cursor.execute("select user_id, active, account_created, password, code from Users where username = ?", (username,)).fetchone()
        if not user:
            return False
        if not user[0]:
            return False
        if user[1] != "y":#if account inactive then code fails
            return False
        if user[3] != None:#if the account already has a password then the employee has allready signed in and this returns false
            return False
        if datetime.datetime.now() - datetime.datetime.strptime(user[2],"%Y-%m-%d %H:%M:%S") > datetime.timedelta(weeks=1):#if code has expired the account is removed
            self._remove_old_code(user[0])
            return False
        return user[4]

    def _remove_old_code(self, userId):
        self._cursor.execute("delete from users where user_id = ?", (userId,))
        self._connection.commit()
        return
    
    def sign_up_employee(self, username:str, comKey:str, signKey:str, passwordHash:str):
        try:
            self._cursor.execute('update Users set password=?, com_key=?, sign_key=?, code=Null where username = ?',
                                (bytes(passwordHash, "utf-8"), comKey, signKey, username))
            self._connection.commit()
            return
        except Exception as e:
            print(e)#not for production
            raise Exception("Falied to sign up employee")



    def create_employee_code(self, username, role, codeHash):
        try:
            self._cursor.execute("INSERT INTO Users(username,code, active, role) VALUES (?, ?, ?, ?)", (username, codeHash, 'y', role))
            self._connection.commit()
        except:
            return False
        return True
        
    def revoke_users_com_key(self, userId):
        self._cursor.execute("update users set com_key = Null where user_id = ?", (userId,))
        self._connection.commit()
        return
        

    def revoke_users_sign_key(self, userId):
        self._cursor.execute("update users set sign_key = Null where user_id = ?", (userId,))
        self._connection.commit()
        return

    def update_user_email(self, userId, email:str):
        self._cursor.execute("update users set email = ? where user_id = ?", (email, userId))
        self._connection.commit()
        return


    def get_user_list(self):
        users = self._cursor.execute("select user_id, username, role, active from users").fetchall()
        return users

AUTH_DATA_BASE = CustomDataBase("Authenticate.db")




def test_cases():
    AUTH_DATA_BASE.remove_test_user("testUser")
    try:
        AUTH_DATA_BASE.add_secret("doesntExist", b"testsecret")
    except Exception as e:
        assert str(e) == "User 'doesntExist' does not exist"
    
    try: 
        AUTH_DATA_BASE.get_user_secret("doesntExist")
    except Exception as e:
        assert str(e) == "User does not exist"

    try:
        AUTH_DATA_BASE.get_user_password("doesntExist")
    except Exception as e:
        assert str(e) == "User does not exist"
    
    assert AUTH_DATA_BASE.create_customer("testUser", "pass", b"sdasdad", b"sdasdasdsad") == None
    
    try:
        AUTH_DATA_BASE.create_customer("testUser", "pass", b"sdasdad", b"sdasdasdsad")
    except Exception as e:
        assert str(e) == "User already exists"

    try:
        AUTH_DATA_BASE.get_user_secret("testUser")
    except Exception as e:
        assert str(e) == "Secret does not exist"
    
    assert AUTH_DATA_BASE.add_secret("testUser", b"testsecret") == None

    try:
        AUTH_DATA_BASE.add_secret("testUser", b"testsecret")
    except Exception as e:
        assert str(e) == "User 'testUser' already has a secret"



test_cases()
try:
    AUTH_DATA_BASE.add_stock("Nvidia", 100.00)
    AUTH_DATA_BASE.add_stock("Oracle", 30.34)
    AUTH_DATA_BASE.add_stock("BMW", 22.57)
    AUTH_DATA_BASE.add_stock("AMD", 33.14)
    AUTH_DATA_BASE.add_stock("INTEL", 22.01)
    AUTH_DATA_BASE.add_stock("Microsoft", 202.56)
except:
    print("failed")


