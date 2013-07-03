import ssl,socket
def hello():
	sock.send("Hello Nigger")
port = 1234
sock = ssl.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
sock.listen(5)
while True:
	obj, conn = sock.accept()
	threading.Thread(target=hello).start()


