from communicate import Communicate
from ServerCrypto import *



def main():
    Communicate.SOCKET, Communicate.ADDR = Communicate.SOCKET.accept()
    while True:
        data = Communicate.read_reply()
        if data is None:
            break
        if data[0] == "sign":
            sign_up(data[1], data[2])





        print("Received data:", data)



main()