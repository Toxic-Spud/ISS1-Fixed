import socket
from ServerCrypto import decrypt_chacha20, encrypt_chacha20, handshake, hkdf_expand_label
from datetime import timedelta, datetime
from os import urandom, write
from base64 import b64encode
from database import User, AUTH_DATA_BASE
from log import INFO_LOGGER

DEMONSTRATION = False


def print(*args):
    if DEMONSTRATION:
        buffer = b""
        for arg in args: buffer += bytes(str(arg), "utf-8") 

        write(1,buffer+b"\n")
    return



class Communicate:

    def __init__(self, bindAddress='127.0.0.1', bindPort=6663, timeout=120):
        print("Binding to address:", bindAddress, "and port:", bindPort)
        self.bindAddress = bindAddress#address to listen on
        self.bindPort = bindPort#port to listen on
        self.timeout = timeout
        
        self.bind()
        self.addr = None#address of the connecting client
        self.usersWithSessions = {}#stores the session id of each logged in user used to remove all sessions of a given user
        self.sessionData = {}#stroes the session data ascosiated with each sessionId
        self.recieverSeqNum = 0#sequence numbers for generating unique nonces
        self.senderSeqNum = 0
        self._delimiter = b","#delimiter used to seperate data
        self._clientComCodes= {"sign", "clog", "buy ", "sell", "hist", "smsg", "rmsg", "rvok", "appr", "logo"}#valid com codes from client
        self._serverComCodes= {"succ", "erro", "info", "cert", "resp"}#valid server com codes
        self._updMsgQueued = False#used to update keys when record containing update message is sent
        self.sendBuffer = b""
        self.recvBuffer = []
        self._senderSecret = None#secrets derived from ECDHE
        self._recieverSecret = None
        self._senderKey = None#Keys derived from the secrets
        self._recieverKey = None
        self._handshakeSequence = ("c hi", "s hi", "cert", "vcer", "sfin", "cfin")#Expected hanshake sequence
        self._handshakePositiion = 0#current position of the handshake ensures that no steps are missed or out of order

    def bind(self):
        self._con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._con.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._con.bind((self.bindAddress, self.bindPort))
        self._con.settimeout(self.timeout)
        self._con.listen(1)


    #gets the data pertaining to a session
    def get_session_data(self, sessionId:str):
        if sessionId not in self.sessionData:
            return None
        data = self.sessionData[sessionId]
        inactiveTime = datetime.now() - data["lastAction"]
        if inactiveTime > timedelta(minutes=5) or (datetime.now() - data["sessionStart"]) > timedelta(hours=24):
            self.end_session(sessionId)#checks that session shouldn't be timed out due to inactivity or session expiry
            return None
        self.record_activity(sessionId)
        return(data)

    #updates session activity
    def record_activity(self, sessionId:str):
        if sessionId not in self.sessionData:
            raise ValueError("Session Id doesnt exist")
        self.sessionData[sessionId]["lastAction"] = datetime.now()
        return

    #Creates a new session id and stores the authenticated user in the sessionData using the id as a key
    def new_session_id(self, username):
        newId = urandom(64)
        newId = b64encode(newId).decode("utf-8") #converts the 64 byte id to a base 64 encoded string
        try:
            user = AUTH_DATA_BASE.get_user(username)
        except:
            return False
        self.usersWithSessions.setdefault(int(user.id), [])
        self.usersWithSessions[int(user.id)].append(newId)
        self.sessionData[newId] = {"user":user, "lastAction":datetime.now(), "sessionStart":datetime.now()}
        return newId

    #Ends session by popping the id out (used when user logs out or session expires)
    def end_session(self, sessionId:str):
        self.sessionData.pop(sessionId)
        return


    #Ends all sessions a user has can be used when making an account inactive or to remove compromised sessions
    #Or if a password is updated
    def close_user_sessions(self, userId:int):
        sessions = self.usersWithSessions.get(userId)
        if sessions != None:
            for session in sessions:
                self.end_session(session)
        return


    def accept(self):
        self._con, self.addr = self._con.accept()
        INFO_LOGGER.info(f"Incoming connection from {self.addr}")
        return 
    


    def close(self):
        self._senderSecret = None
        self._recieverSecret = None
        self._recieverKey = None
        self._senderKey = None
        self.senderSeqNum = 0
        self.recieverSeqNum = 0
        self._handshakePositiion = 0
        try:
            self._con.shutdown()
            self._con.close()
        except:
            print("Socket already closed")
        self._updMsgQueued = False
        self.sendBuffer = b""
        self.recvBuffer = []
        return


    #calculates updated application secrets in accordance with rfc 8446 specification
    def rekey(self):
        print("Rekeying application keys")
        self._updMsgQueued = False
        newSenderSecret = hkdf_expand_label(self._senderSecret, b"upd", b"", 32)
        newRecvSecret = hkdf_expand_label(self._recieverSecret, b"upd", b"", 32)
        self.set_secrets(newSenderSecret, newRecvSecret)
        self.keys_from_secrets()
        return


    #sets new updated secrets
    def set_secrets(self, me, reciever):
        self._senderSecret = me
        self._recieverSecret = reciever
        return

    #uses newly derived secret to derive new application keys in accordance with rfc 8446
    def keys_from_secrets(self):
        if self._senderSecret == None or self._recieverSecret == None:
            raise ValueError("Secrets have not been set")
        sendKey = hkdf_expand_label(self._senderSecret, b"key", b"", 32)
        sendIv = hkdf_expand_label(self._senderSecret, b"iv", b"", 12)
        recvKey = hkdf_expand_label(self._recieverSecret, b"key", b"", 32)
        recvIv = hkdf_expand_label(self._recieverSecret, b"iv", b"", 12)
        self.set_keys((sendKey,sendIv), (recvKey, recvIv))
        return

    #sets new keys and resets sequence numbers in accordance with RFC 8446 specification
    def set_keys(self, me, reciever):
        self.recieverSeqNum = 0
        self.senderSeqNum = 0
        self._senderKey = me
        self._recieverKey = reciever
        return

    #encrypts message and includes length of message as authenticated data
    def enc_data(self, res):
        try:
            header = (len(res)+32).to_bytes(4,"big")
            res = encrypt_chacha20(res, self._senderKey[0], self._senderKey[1], self.senderSeqNum, header)
        except Exception as e:
            self.close()
            raise e
        self.senderSeqNum += 1
        return res

    #decrypts message and checks expected sequence number and sequence number of msg match
    def dec_data(self, data):
        iv = self._recieverKey[1]
        expectedNonce = bytes(abyte ^ bbyte for abyte, bbyte in zip(iv, self.recieverSeqNum.to_bytes(12, 'big')))
        try:            
            res = decrypt_chacha20(data, self._recieverKey[0], expectedNonce)
        except Exception as e:
            self.close()#if integrity check or expected nonce fail catch error and terminate cconnection
            raise e
        self.recieverSeqNum += 1
        return res

    #serializes data and adds it to buffer
    def add_to_buffer(self, action, data):
        if (self.senderSeqNum >= 10) and not self._updMsgQueued:
            self._updMsgQueued = True
            self.add_to_buffer("upda", ["update application keys"])
        res = self._delimiter + bytes(action, "utf-8")
        for item in data:
            if not isinstance(item, bytes):
                item = bytes(item, "utf-8")
            res += len(item).to_bytes(2,"big") + self._delimiter + item
        self.sendBuffer += res
        return

    #Sends data in buffer
    def send_buffer(self):
        if self._handshakePositiion >= 2:
            print(f"Encrypting Data: {self.sendBuffer}\n\n\n")
            payload = self.enc_data(self.sendBuffer)#will throw error if no keys so data will never accidently be sent in the clear
            print(f"Sending Encrypted data Data: {payload}\n\n\n")
        else:
            payload = (len(self.sendBuffer)+4).to_bytes(4,"big") + self.sendBuffer
        self._con.sendall(payload)
        self.sendBuffer = b""
        if self._updMsgQueued:
            self.rekey()
        return
    

    #wrapper around add_to_buffer() and send_buffer()
    def send(self, action, data):
        self.add_to_buffer(action, data)
        self.send_buffer()
        return



    def recv_buffer(self): #ensures data larger than the networks MTU is read in its entirety
        data = self._con.recv(1024)
        if data == b"":
            self.close()
            raise Exception("Session closed by client")
        totLength = int.from_bytes(data[:4], "big")#get length of all the data
        result = data
        while len(result) < totLength:#keeps reading data until expected amount of data is read
            data = self._con.recv(min(1024, totLength - len(result)))
            result += data
        if self._handshakePositiion >=2:#if client and server hello have happened the data needs to be decrypted
            result =self.dec_data(result)
        else:
            result = result[4:]
        buffer = []
        print(f"Recieving encrypted data: {result}: \n\n\n")
        i= -1
        while result != b"": #splits data into seperate messages and splits messages into headers and data
            if result[0] == self._delimiter[0]:
                buffer.append([])
                i += 1
                buffer[i].append(result[1:5].decode("utf-8"))
                if buffer[i][0] == "upda" and self._handshakePositiion >= 6:
                    self.rekey()#if message is an update message rekey session
                result = result[5:]
            else:
                dataLen = int.from_bytes(result[:2], "big")
                result = result[3:]
                buffer[i].append(result[:dataLen])
                result = result[dataLen:]
        print(f"Decrypted data: {buffer}: \n\n\n")
        self.recvBuffer = buffer
        return
    

    
    def initiate_handshake(self):
        try:
            res = handshake(self)
            INFO_LOGGER.info(f"connection from {self.addr} successfully completed handshake")
            return res
        except Exception as e:#record failed hand shake and pass error up
            INFO_LOGGER.info(f"connection from {self.addr} failed to complete handshake")
            raise e
    

    #gets msg from the buffer, calls recv_buffer() if no messages in buffer 
    #skips over upda msgs as they are handled by send_buffer, and recv_buffer
    def get_message(self):
        if len(self.recvBuffer) <= 0:
            self.recv_buffer()
        msg = self.recvBuffer[0]
        self.recvBuffer = self.recvBuffer[1:]#removes the first msg from buffer
        if msg[0] == "upda":
            return self.get_message()
        return(msg)#returns the first message in the buffer


    #Reads the next msg in the handshake
    #detects attempts to redo handshake after a handshake has already been established and throws an error
    def read_handshake(self):
        if self._handshakePositiion >= 6:
            self.close()
            raise ValueError("Handshake already completed")
        msg = self.get_message()
        if msg[0] != self._handshakeSequence[self._handshakePositiion]:
            self.close()
            raise ValueError("Handshake out of order")
        if self._handshakePositiion == 0:
            result = self.check_hello(msg[1:])
        elif self._handshakePositiion == 5:
            result = msg[1:]
        else:
            self.close()
            raise ValueError("Read handshake called before correct step in handshake")
        self._handshakePositiion += 1
        return result

    #ensures that the hello contains valid data
    def check_hello(self, msg):
        if len(msg) != 2 or len(msg[0]) != 32 or len(msg[1]) != 32:
            self.close()
            raise ValueError("Invalid hello message")
        return msg
    

    def send_hello(self, data):
        if self._handshakePositiion != 1:
            self.close()
            raise ValueError("No client hello received yet")
        self.add_to_buffer("s hi", data)
        self.send_buffer()
        self._handshakePositiion += 1
        return
    

    def send_cert(self, certificate):
        if self._handshakePositiion != 2:
            self.close()
            raise ValueError("Out of order handshake")
        self.add_to_buffer("cert", [certificate])
        self._handshakePositiion += 1
        return
    
    def send_verify(self, signature):
        if self._handshakePositiion != 3:
            self.close()
            raise ValueError("Out of order handshake")
        self.add_to_buffer("verf", [signature])
        self._handshakePositiion += 1
        return
    
    def send_finish(self, hashMac:bytes):
        if self._handshakePositiion != 4:
            self.close()
            raise ValueError("Out of order handshake")
        self.add_to_buffer("sfin", [hashMac])
        self.send_buffer()
        self._handshakePositiion += 1
        return
    
   
        

    
    