from signup import sign_up
from communicate import Communicate



def main():
    choice = ''
    while choice != 's' and choice != 'l' or 'e':
        print("Welcome to Finance Tracker!")
        print("Sign up (s) or Log in (l)")
        print("Enter s or l: ")
        choice = input().strip()
        if choice == 's':
            sign_up()
        elif choice == 'l':
            pass
        else:
            print("Invalid choice. Please enter 's' for sign up or 'l' for log in.")
    Communicate.SOCKET.close()
    print("Goodbye!")



main()


