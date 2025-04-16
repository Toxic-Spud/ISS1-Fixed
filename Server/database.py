from pysqlcipher3 import dbapi2 as sqlite3
import os
import shutil
import datetime
from Crypto.Cipher import AES


class CustomDataBase:
    def __init__(self, dbFile):
        self._dbFile = dbFile
        self._connection = sqlite3.connect(self._dbFile)
        self._cursor = self._connection.cursor()
        self.key = b'9\xfd\xe4\xad\r\xa10\xe2l\xc0\xa7 \xda\xdb\xd5ep$\xae\xfd\x0cz\xfd\xea\xde\x97\xc8M\x9f_DK'
        self.kek = b'q\x0e\xcdMF\xd2\x19w/\xf8\xca(0\x96}BN\x94\x8f\xc4;}\x83.\xb8\x88$B\xc1\xb3l['
        self._cursor.execute(f"PRAGMA key = \"x'{self.key.hex()}\"")
        try:
            self._cursor.execute("drop table Users")
        except sqlite3.OperationalError:
            print("Passed")
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

        self.initial_setup()
    
    def initial_setup(self):
        self._cursor.execute("""CREATE TABLE Roles (
                role_id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
                )""")
        self._cursor.execute("""CREATE TABLE Users (
                user_id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password bytea,
                secret bytea,
                com_key bytea,
                sign_key bytea,
                active varchar(1),
                role INTEGER,
                foreign KEY(role) references Roles(role_id)
                )""")
        self._cursor.execute("""CREATE TABLE Employee_Customer (
                pair_id INTEGER PRIMARY KEY,
                employee INTEGER NOT NULL,
                customer INTEGER NOT NULL,
                FOREIGN KEY (employee) REFERENCES Users(user_id)
                FOREIGN KEY (customer) REFERENCES Users(user_id)
                )""")
        self._cursor.execute("""CREATE TABLE Transactions(
                trans_id INTEGER PRIMARY KEY,
                employee INTEGER NOT NULL,
                customer INTEGER NOT NULL,
                FOREIGN KEY (employee) REFERENCES Users(user_id),
                FOREIGN KEY (customer) REFERENCES Users(user_id)
                )""")
        
        

    def get_user_password(self, username):
        result = self._cursor.execute("SELECT password FROM Users WHERE username = ?", [username]).fetchone()
        if result == None:
            raise Exception("User does not exist")
        if result[0] == None:
            raise Exception("User has no password")
        if result:
            return result[0][0]
        return None

    def get_user_secret(self, username):
        result = self._cursor.execute("SELECT secret FROM Users WHERE username = ?", [username]).fetchone()
        if result == None:
            raise Exception("User does not exist")
        if result[0] == None:
            raise Exception("Secret does not exist")
        return result[0][0]
    
    def create_user(self, username, password):
        try:
            self._cursor.execute('INSERT INTO Users (username, password) VALUES (?, ?)',
                                (username, bytes(password, "utf-8")))
            self._connection.commit()
        except:
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
        
    def table_wipe(self):
        self._cursor.execute("delete from Users")
    


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



AUTH_DATA_BASE = CustomDataBase("Authenticate.db")




def test_cases():
    AUTH_DATA_BASE.table_wipe()
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
    
    assert AUTH_DATA_BASE.create_user("testUser", "pass") == None
    
    try:
        AUTH_DATA_BASE.create_user("testUser", "pass")
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
