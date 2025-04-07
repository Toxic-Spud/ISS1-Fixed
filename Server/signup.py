from ServerCrypto import new_password, new_TOTP
from communicate import Communicate
from database import AUTH_DATA_BASE




def sign_up(username, password):
    if username == None or password == None:
        return False
    try:
        AUTH_DATA_BASE.create_user(username, new_password(password))
        TotpSecret = new_TOTP(username)
        Communicate.send("totp", [TotpSecret])
    except Exception as e:
        print(e.args[0])
        Communicate.send("fail", ["User Taken"])
        return False
    return True