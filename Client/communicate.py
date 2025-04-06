import socket





class Communicate:
    SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SOCKET.connect(('localhost', 6666))
    DELIMITIER = ","


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
        except Exception as e:
            print("Error in reading reply:", e)
            return None
        return res
