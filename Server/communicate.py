import socket





class Communicate:
    SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SOCKET.bind(('192.168.0.62', 6666))
    SOCKET.settimeout(120)
    SOCKET.listen(1)
    ADDR = None
    DELIMITIER = ","
    clientComCodes= {"totp", "sign", "logn", "buyy", "sell", "info"}


    @classmethod
    def send(cls,action, data):
        res = action
        for item in data:
            res += str(len(item)) + Communicate.DELIMITIER + item
        res = bytes(res, "utf-8")
        Communicate.SOCKET.sendall(res)
        return

    
    @classmethod
    def read_reply(cls):
        
        data = Communicate.SOCKET.recv(1024)
        data = data.decode("utf-8")
        if data == "":
            return None
        try:
            index = data.find(Communicate.DELIMITIER)
            length = int(data[4:index])
            res = []
            res.append(data[:4])
            while data:
                item = data[index + 1 : index + 1 + length]  
                res.append(item)
                data = data[index + 1 + length :] 
                index = data.find(Communicate.DELIMITIER)
                if index == -1:
                    break
                length = int(data[:index]) 
            if res[0] not in Communicate.clientComCodes:
                raise ValueError("Invalid action code")
        except Exception as e:
            print("Error in reading reply:", e)
            return None
        return res