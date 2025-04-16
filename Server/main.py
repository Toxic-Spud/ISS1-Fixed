from communicate import Communicate
from signup import sign_up
from actions import login


class user:
    def __init__(self, username):
        self.username = username
        self.publicKeys
        self.role

def main():
    cont = "continue"
    connection = Communicate()
    while cont == "continue":
        connection.accept()
        connection.initiate_handshake()
        while True:
            data = connection.get_message()
            if data is None:
                break
            if data[0] == "sign":
                print("signing up")
                sign_up(connection, data[1].decode("utf-8"), data[2].decode("utf-8"))
            elif data[0] == "clog":
                login(connection, data[1], data[2], data[3])
            elif data[0] == "buy ":
                customer_login(connection, data[1], data[2], data[3])
            elif data[0] == "sell ":
                customer_login(connection, data[1], data[2], data[3])
            elif data[0] == "msg ":
                customer_login(connection, data[1], data[2], data[3])
            elif data[0] == "hist":
                customer_login(connection, data[1], data[2], data[3])
        q = str(input("Continue? (c/e): "))
        if q == "e":
            cont = "exit"
        connection.close()
            





        print("Received data:", data)



main()