import sqlite3




class CustomDataBase:
    def __init__(self, dbFile):
        self._dbFile = dbFile
        self._connection = sqlite3.connect(self._dbFile)

    def get_user_password(self, username):
        result = self._connection.execute("SELECT password FROM Users WHERE username = ?", [username]).fetchall()
        print(result)
        if len(result) > 1:
            raise Exception("Only one result expected")
        if result:
            return result[0][0]
        return None

    def get_user_secret(self, username):
        result = self._connection.execute("SELECT secret FROM Users WHERE username = ?", [username]).fetchall()
        if len(result) > 1:
            raise Exception("Only one result expected")
        if result:
            return result[0][0]
        return None
    
    def create_user(self, username, password):
        try:
            self._connection.execute('INSERT INTO Users (username, password) VALUES (?, ?)',
                                (username, bytes(password, "utf-8")))
            self._connection.commit()
        except sqlite3.IntegrityError:
            raise Exception("Username already exists")
    
    def add_secret(self, username, secret):
        try:
            self._connection.execute("UPDATE Users SET secret=? WHERE username=?", (secret, username))
            self._connection.commit()
        except sqlite3.IntegrityError:
            raise Exception("Failed to update secret")



AUTH_DATA_BASE = CustomDataBase("Authenticate.db")