import socket
from ClientCrypto import encrypt_chacha20, decrypt_chacha20, handshake, hkdf_expand_label




class Communicate:

    def __init__(self, bindAddress='localhost', bindPort=6666, timeout=120):
        self._targetAddress = bindAddress
        self._targetPort = bindPort
        self.timeout = timeout
        self.connect()
        self.senderSeqNum = 0
        self.sessionId = None
        self.recieverSeqNum = 0
        self._delimiter = b","
        self._clientComCodes= {"sign", "clog", "buy ", "sell", "info", "elog", "alog", "test", "c hi"}
        self._serverComCodes= {"succ", "erro", "info", "s hi", "cert", "resp", "totp", "fail"}
        self._updMsgQueued = False
        self.sendBuffer = b""
        self.recvBuffer = []
        self._senderSecret = None
        self._recieverSecret = None
        self._recieverKey = None
        self._senderKey = None
        self._handshakeSequence = ("c hi", "s hi", "cert", "verf", "sfin", "cfin")
        self._handshakePositiion = 0


    def connect(self):
        self._con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._con.connect((self._targetAddress, self._targetPort))
        self._con.settimeout(self.timeout)
        return

    def close(self):
        self._senderSecret = None
        self._recieverSecret = None
        self._recieverKey = None
        self._senderKey = None
        self.senderSeqNum = 0
        self.recieverSeqNum = 0
        self._handshakePositiion = 0
        self._updMsgQueued = False
        self.sendBuffer = b""
        self.recvBuffer = []
        try:
            self._con.close()
        except:
            print("connection already closed")
        return


    #calculates updated application secrets in accordance with rfc 8446 specification
    def rekey(self):
        print("rekeying")
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
            header = (len(res)+30).to_bytes(2,"big")
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
            self.close()
            raise e
        self.recieverSeqNum += 1
        return res

    #serializes data and adds it to buffer
    def add_to_buffer(self, action, data):
        if (self.senderSeqNum >= 10) and not self._updMsgQueued:
            self._updMsgQueued = True
            self.add_to_buffer("upda", ["update application keys"])
        if self._handshakePositiion < 2 and action != "c hi" and action != "s hi":
            raise Exception("Complete handshake before sending data")
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
            payload = (len(self.sendBuffer)+2).to_bytes(2,"big") + self.sendBuffer
        self._con.sendall(payload)
        self.sendBuffer = b""
        if self._updMsgQueued:
            self.rekey()
        return
    
    #wrapper around add_to_buffer() and send_buffer()
    def send(self, action, data, id=None):
        if id:
            data.append(self.sessionId)
        self.add_to_buffer(action, data)
        self.send_buffer()
        return



    def recv_buffer(self): #ensures data larger than the networks MTU is read in its entirety
        data = self._con.recv(1024)
        print(f"Recieving encrypted data: {data} \n\n\n")
        if data == b"":
            self.close()
            raise Exception("Session closed by server")
        totLength = int.from_bytes(data[:2], "big")#get length of all the data
        result = data
        while len(result) < totLength:#keeps reading data until expected amount of data is read
            data = self._con.recv(min(1024,  totLength - len(result)))
            result += data
        if self._handshakePositiion >=2:#if client and server hello have happened the data needs to be decrypted
            result =self.dec_data(result)
        else:
            result = result[2:]
        buffer = []
        i= -1
        while result != b"": #splits data up into its seperate messages and splits each message into the comCode and the data
            if result[0] == self._delimiter[0]:
                buffer.append([])
                i += 1
                buffer[i].append(result[1:5].decode("utf-8"))
                if buffer[i][0] == "upda" and self._handshakePositiion >= 6:
                    self.rekey()
                result = result[5:]
            else:
                dataLen = int.from_bytes(result[:2], "big")
                result = result[3:]
                buffer[i].append(result[:dataLen])
                result = result[dataLen:]
        self.recvBuffer = buffer
        print(f"Recieving data: {buffer} \n\n\n")
        return
    

    
    def initiate_handshake(self):
        return handshake(self)
    

    #gets msg from the buffer, calls recv_buffer() if no messages in buffer 
    #skips over upda msgs as they are handled by send_buffer, and recv_buffer
    def get_message(self):
        if len(self.recvBuffer) <= 0:
            self.recv_buffer()
        if len(self.recvBuffer) <= 0:
            raise IndexError("No messages in the buffer")
        msg = self.recvBuffer[0]
        self.recvBuffer = self.recvBuffer[1:]
        if msg[0] == "upda":
            return self.get_message()
        return(msg)


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
        if self._handshakePositiion == 1:
            result = self.check_hello(msg[1:])
        elif self._handshakePositiion == 2:
            result = msg[1:]
        elif self._handshakePositiion == 3:
            result = msg[1:]
        elif self._handshakePositiion == 4:
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
        if self._handshakePositiion != 0:
            self.close()
            raise ValueError("No client hello received yet")
        self.add_to_buffer("c hi", data)
        self.send_buffer()
        self._handshakePositiion += 1
        return
    

    
    
    def send_finish(self, hashMac:bytes):
        if self._handshakePositiion != 5:
            self.close()
            raise ValueError("Out of order handshake")
        self.add_to_buffer("cfin", [hashMac])
        self.send_buffer()
        self._handshakePositiion += 1
        return