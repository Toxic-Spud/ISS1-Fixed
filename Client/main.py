from signup import sign_up
from communicate import Communicate
from login import log_in
from time import sleep


def reconnect(connection):
    sleep(0.5) #wait before reconnect
    


def main():
    connection = Communicate()
    connection.initiate_handshake()
    choice = ''
    while choice != 'e':
        print("Welcome to Finance Tracker!")
        print("Sign up (s) or Log in (l)")
        print("Enter s or l: ")
        choice = input().strip()
        if choice == 's':
            try:
                sign_up(connection)
            except:
                print("Error occured attempting to reconnect")
                connection.reconnect()
        elif choice == 'l':
            log_in(connection)
        else:
            print("Invalid choice. Please enter 's' for sign up or 'l' for log in.")
    connection.close()
    print("Goodbye!")



main()


