import ssl,socket
s = ssl.socket()
your_port =1234
s.connect(('68.193.204.138',your_port))
data=s.recv(5)
s.close()
