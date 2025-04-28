import tkinter
from PIL import ImageTk
import pyotp
import qrcode
import hashlib



def get_qrcode(secret, username):
    totp = pyotp.TOTP(secret, interval=30, digits=8, digest=hashlib.sha256)
    qrcode_img = qrcode.make(totp.provisioning_uri(name=username, issuer_name="Finance App"))
    return qrcode_img



def show_qr_code(qrCode):
    window = tkinter.Tk()
    codeImage = ImageTk.PhotoImage(qrCode)
    window.title("QR Code")
    window.geometry(str(codeImage.height()) + "x" + str(codeImage.width()))
    window.resizable(False, False)
    window.configure(bg="white")
    label = tkinter.Label(window, image=codeImage, bg="white")
    label.pack()
    window.mainloop()

