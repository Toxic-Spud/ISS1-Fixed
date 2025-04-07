from communicate import Communicate
from signup import sign_up
from Authentication import customer_login



def main():
    Communicate.SOCKET, Communicate.ADDR = Communicate.SOCKET.accept()
    print("Connection from:", Communicate.ADDR)
    while True:
        data = Communicate.read_reply()
        if data is None:
            break
        if data[0] == "sign":
            sign_up(data[1], data[2])
        if data[0] == "clog":
            customer_login(data[1], data[2], data[3])
        





        print("Received data:", data)



main()