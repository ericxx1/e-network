import sys, re, os, socket, binascii, threading, time, urllib
from random import randint
from multiprocessing import Process
from threading import Thread
import random
import uuid
import rsa
from rsa import *
import base64
import aes
import traceback
print("Welcome to the e network client v0.001");
if os.path.isfile('id/destination'):
	print("Destination file found. Loading....");
else:
	print("Destination file not found. Creating a new destination....");
	randnum = str(randint(1111111111111111,9999999999999999));
	f = open('id/destination', 'w+');
	f.write('-enet0.001-' + randnum);
	f.close;
	print("New Destination created!");
f = open('id/destination');
your_destination = f.read();
your_destination = your_destination.strip();
f.close;
print('Your Destination is:' + your_destination);	
print "Using SOCKS6v001 Auth Beta Test"
global publickey
global privatekey
if os.path.isfile('keys/private'):
	print ("Private Key found");
else:
	print "Public-private key combo has not been found. Generating a new one. This will  take some time. Please wait.."
	publickey, privatekey = rsa.newkeys(1024)
	p = open("keys/public", "w+")
	p.write(str(publickey))
	p.close
	p = open("keys/private", "w+")
	p.write(str(privatekey))
	p.close
	print "New keys generated!"
p = open("keys/public", "r")
publickey = p.read()
p.close()
p = open("keys/private", "r")
privatekey = p.read()
p.close()
"Print public-private keys loaded!"	
		
"""define auth packets"""
SOCKS6_VER = "\x06"
SOCKS6_NULL = "\x00"
SOCKS6_AUTH = "\x00"
SOCKS6_SUCCESS = "\x03"
SOCKS6_OKAY = "\x01"
SOCKS6_SOCKFAIL = "\x66"
SOCKS6_ESTABLISHED = "\x09"
SOCKS6_REQUEST = "\x08"
SOCKS6_TERM = "\x00"
SOCKTIMEOUT=5#
RESENDTIMEOUT=300#

VER="\x05"
METHOD="\x00"

SUCCESS="\x00"
SOCKFAIL="\x01"
NETWORKFAIL="\x02"
HOSTFAIL="\x04"
REFUSED="\x05"
TTLEXPIRED="\x06"
UNSUPPORTCMD="\x07"
ADDRTYPEUNSPPORT="\x08"
UNASSIGNED="\x09"

_LOGGER=None

class Log:
	WARN="[WARN:]"
	INFO="[INFO:]"
	ERROR="[ERROR:]"
	def write(self,message,level):
		pass
		
class SocketTransform(Thread):
	def __init__(self,node_pub_key,src,dest_ip,dest_port,bind=False):
		Thread.__init__(self)
		self.dest_ip=dest_ip
		self.dest_port=dest_port
		self.src=src
		self.bind=bind
		self.setDaemon(True)
		self.node_pub_key=node_pub_key
		#print "Sockettrans: " + self.node_pub_key

	def run(self):
		try:
			self.resend()
		except Exception,e:
			traceback.print_exc()
			print("Error on SocketTransform %s" %(e.message,),Log.ERROR)
			self.sock.close()
			self.dest.close()

	def resend(self):
		self.sock=self.src
		self.dest=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.dest.connect((self.dest_ip,self.dest_port))
		self.node_pub_key=self.node_pub_key
		if self.bind:
			print("Waiting for the client")
			self.sock,info=sock.accept()
			print("Client connected")
		print("Starting Resending")
		self.sock.settimeout(RESENDTIMEOUT)
		self.dest.settimeout(RESENDTIMEOUT)
		DecryptedResender(self.sock,self.dest).start()
		CryptedResender(self.dest,self.sock,self.node_pub_key).start()
"""Normal Resender
class Resender(Thread):
	def __init__(self,src,dest):
		Thread.__init__(self)
		self.src=src
		self.setDaemon(True)
		self.dest=dest

	def run(self):
		try:
			self.resend(self.src,self.dest)
		except Exception,e:
			print("Connection lost %s" %(e.message,),Log.ERROR)
			self.src.close()
			self.dest.close()

	def resend(self,src,dest):
		data=src.recv(10)
		while data:
			dest.sendall(data)
			data=src.recv(10)
		src.close()
		dest.close()
		print("Client quit normally\n")		
"""				
class CryptedResender(Thread):
	def __init__(self,src,dest,node_pub_key):
		Thread.__init__(self)
		self.src=src
		self.setDaemon(True)
		self.dest=dest
		self.node_pub_key=node_pub_key

	def run(self):
		try:
			self.resend(self.src,self.dest,self.node_pub_key)
		except Exception,e:
			traceback.print_exc()
			print("Connection lost %s" %(e.message,),Log.ERROR)
			self.src.close()
			self.dest.close()

	def resend(self,src,dest,node_pub_key):
		aeskey = str(uuid.uuid4().hex) # Generate new AES Key
		key = encrypt(aeskey, eval(str(node_pub_key))) # Encrypt AES key with target's RSA Public Key
		key = base64.b64encode(key) # Base64 encode the key
		print "Sent this base64 encoded key: " + key
		dest.sendall(key)
		data=src.recv(10)		
		print "node's public key:"+ node_pub_key
		while data: 
			crypted_data = aes.encryptData(aeskey,data) # Encrypt Message with AES Key 
			crypted_data = base64.b64encode(crypted_data) # Base64 encode the crypted data
			print "Sent this Crypted Data: " + crypted_data
			dest.sendall(crypted_data)
			data=src.recv(10)
		src.close()
		dest.close()
		print("Client quit normally\n")
		
class DecryptedResender(Thread):
	def __init__(self,src,dest):
		Thread.__init__(self)
		self.src=src
		self.setDaemon(True)
		self.dest=dest

	def run(self):
		try:
			self.resend(self.src,self.dest)
		except Exception,e:
			traceback.print_exc()
			print("Connection lost %s" %(e.message,),Log.ERROR)
			self.src.close()
			self.dest.close()

	def resend(self,src,dest):
		key = src.recv(172)
		print "Received this base64 encoded aes key: " + key
		aeskey = decrypt(base64.b64decode(key), eval(privatekey))
		data=src.recv(44)
		print "Your pub key:"+str(publickey)
		while data: 
			print "Received this crypted data: " + data
			uncrypted=aes.decryptData(str(aeskey), base64.b64decode(str(data)))#.encode("utf-8")	
			print uncrypted
			dest.sendall(uncrypted)
			data=src.recv(44)
		src.close()
		dest.close()
		print("Client quit normally\n")							

class MainNode():
	global your_port
	global connector_port
	config = open("config.txt", "r")
	configlist = config.readlines()
	config.close()
	for line in configlist:
		if line.find("your_port:") != -1:
			line = line.replace('"', "").strip("your_port:").strip("\n")
			your_port = int(line)
			print "Port to start server: " + str(your_port)
		if line.find("connector_port:") != -1:
				line = line.replace('"', "").strip("connector_port:").strip("\n")
				connector_port = int(line)				
	def create_server(self):
		print "Starting Socks6 node auth server.." 
		your_port = 3233
		nodes = []
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.bind(('',your_port))
		s.listen(1000)
		while True:
			global client
			client, addr = s.accept()
			packet = client.recv(1)
			if packet == SOCKS6_NULL:
				print "Client connected.. ["+str(addr)+"]"
				cli_ver, cli_null, cli_request, node_destination, node_ip, node_port, node_pub_key, cli_term=(client.recv(1), client.recv(1), client.recv(1), client.recv(27), client.recv(32), client.recv(4),client.recv(326), client.recv(1))
				list1 = re.findall("........", node_ip)
				node_ip = [str(int(n, 2)) for n in list1]
				node_ip = '.'.join(node_ip)
				print ("Got these packets: " + cli_ver + ":" + cli_null + ":" + cli_request + ":" + node_destination + ":" + node_ip + ":" + node_port + ":" + cli_term)
				if (cli_ver == SOCKS6_VER and cli_null == SOCKS6_NULL and cli_request == SOCKS6_REQUEST and cli_term == SOCKS6_TERM):
					nodes.append(node_destination + ":" + node_ip + ":" + node_port)
					found = False
					for node in nodes:
						nodefile = open("nodes.db", "r")
						nodelist = nodefile.readlines()
						print "nodelist:" + str(nodelist)
						nodefile.close()
						for line in nodelist:					
							if node in line:
								print "Found node"
								found = True
						if not found:
							nodefile = open("nodes.db", "a+")
							nodefile.write(node+":"+node_pub_key)	
							nodefile.close()
							print "Wrote new node to file"	
					client.sendall(SOCKS6_OKAY+SOCKS6_AUTH+SOCKS6_OKAY+SOCKS6_SUCCESS+SOCKS6_ESTABLISHED)
					print "Connection with " + node_destination + " established "
			elif packet == VER:
				print "Got a Socks5 client request.."
				RelayList = open("nodes.db").read().splitlines()
				randomnode = random.choice(RelayList)
				node_destination, node_ip, node_port, node_pub_key = randomnode.split(":")
				node_pub_key = node_pub_key.strip("\n")
				print "Connecting to Relay: " + node_destination
				o = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				o.connect((node_ip, int(node_port)))
				o.send("5")
				print "Sent 5 Packet"
				print "Sent Version"
				cli_ver, cli_nmethods, cli_methods = (VER,client.recv(1),client.recv(1))
				o.sendall(cli_ver+cli_nmethods+cli_methods)
				serv_ver, serv_method = (o.recv(1), o.recv(1))
				client.send(serv_ver+serv_method)
				print serv_ver + serv_method
				cli_ver, cli_cmd, cli_rsv, cli_atyp=(client.recv(1),client.recv(1),client.recv(1),client.recv(1))
				o.sendall(cli_ver+cli_cmd+cli_rsv+cli_atyp)
				cli_addr_len=client.recv(1)
				o.send(cli_addr_len)
				cli_addr_len=ord(cli_addr_len)
				cli_dst_addr,cli_dst_port = (client.recv(cli_addr_len),client.recv(2))
				o.sendall(cli_dst_addr+cli_dst_port)
				cli_ver,cli_success,cli_null,cli_byte,cli_server_ip,cli_port1,cli_port2 = (o.recv(1),o.recv(1),o.recv(1),o.recv(1),o.recv(4),o.recv(1),o.recv(1))
				client.send(cli_ver+cli_success+cli_null+cli_byte+cli_server_ip+cli_port1+cli_port2)
				print "SENT"
				CryptedResender(client,o,node_pub_key).start()
				DecryptedResender(o,client).start()	
			elif packet == "domain":
				domain_info = client.recv(4096)
				domain_file_name, domain_ip = domain_info.split(":")
				new_doman = open(domain_file_name, "w+")
				new_domain.write(domain_ip.strip()+"\n")
				new_domain.close();									
			elif packet == "5":
				print "Got a connection"
				try:
					ip="0.0.0.0"
					port=3233
					client.settimeout(SOCKTIMEOUT)
					ver,nmethods,methods=(client.recv(1),client.recv(1),client.recv(1))
					client.sendall(VER+METHOD)
					ver,cmd,rsv,atyp=(client.recv(1),client.recv(1),client.recv(1),client.recv(1))
					dst_addr=None
					dst_port=None
					if atyp=="\x01":#IPV4
						dst_addr,dst_port=client.recv(4),client.recv(2)
						dst_addr=".".join([str(ord(i)) for i in dst_addr])
					elif atyp=="\x03":#Domain
						addr_len=ord(client.recv(1))#
						dst_addr,dst_port=client.recv(addr_len),client.recv(2)
						dst_addr="".join([unichr(ord(i)) for i in dst_addr])
					elif atyp=="\x04":#IPV6
						dst_addr,dst_port=client.recv(16),client.recv(2)
						tmp_addr=[]
						for i in xrange(len(dst_addr)/2):
							tmp_addr.append(unichr(ord(dst_addr[2*i])*256+ord(dst_addr[2*i+1])))
						dst_addr=":".join(tmp_addr)
					dst_port=ord(dst_port[0])*256+ord(dst_port[1])
					print("Client wants to connect to %s:%d" %(dst_addr,dst_port))
					server_client=client
					server_ip="".join([chr(int(i)) for i in ip.split(".")])
					print "server ip: " + server_ip
					if cmd=="\x02":#BIND
						#Unimplement
						client.close()
					elif cmd=="\x03":#UDP
						#Unimplement
						client.close()
					elif cmd=="\x01":#CONNECT
						client.sendall(VER+SUCCESS+"\x00"+"\x01"+server_ip+chr(port/256)+chr(port%256))
						print("Starting transform thread")
						if dst_addr.find ('www.') != -1:
							dst_addr = dst_addr.replace("www.", '');
						f = open('destinations/' + dst_addr);
						dst_addr_com = f.read();
						f.close();
						dst_addr_com = dst_addr_com.strip();
						print(dst_addr_com, dst_port);
						SocketTransform(node_pub_key,server_client,dst_addr_com,int(dst_port)).start()											
					else:#Unsupported Command
						client.sendall(VER+UNSPPORTCMD+server_ip+chr(port/256)+chr(port%256))
						client.close()
				except Exception,e:
					print("Error on starting transform:"+e.message,Log.ERROR)
					client.close()										
	def connect_to_nodes(self):
		print "Connecting to nodes"
		global your_destination
		global publickey
		global node_pub_key
		connector_port = 3122
		group = re.compile(u'(?P<ip>\d+\.\d+\.\d+\.\d+)').search(urllib.URLopener().open('http://jsonip.com/').read()).groupdict()
		your_ip = group['ip']
		bin_ip = [bin(int(n))[2:].zfill(8) for n in your_ip.split(".")]
		bin_ip = "".join(bin_ip)
		c = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		c.bind(('', connector_port))
		nodes = open("nodes.db")
		nodeslist = nodes.readlines()
		nodes.close()
		print nodeslist
		print "Beginning to connect to nodes...."
		for line in nodeslist:
			destination, ip, port, node_pub_key = line.split(":")	
			destination = destination.strip()
			ip = ip.strip()
			port = port.strip()
			node_pub_key = node_pub_key.strip()
			if your_destination != destination:
				print "Connecting to node: " + destination
				try:
					c.connect((ip,int(port)))
				except("socket.error","error"):
					print "Error connecting to node: " + destination
					pass
				global your_port
				c.sendall(SOCKS6_NULL+SOCKS6_VER+SOCKS6_NULL+SOCKS6_REQUEST+your_destination+bin_ip+str(your_port)+str(publickey)+SOCKS6_NULL)
				print "Sent Socks6 Auth Header"
				time.sleep(1)
				serv_okay, serv_auth, serv_okay, serv_sucss, serv_estab=(c.recv(1), c.recv(1), c.recv(1), c.recv(1), c.recv(1))
				print ("Got these packets: " + serv_okay + ":" + serv_auth + ":" + serv_okay + ":" + serv_sucss + ":" + serv_estab)
				if (serv_okay == SOCKS6_OKAY and serv_auth == SOCKS6_AUTH and serv_okay == SOCKS6_OKAY and serv_sucss == SOCKS6_SUCCESS and serv_estab == SOCKS6_ESTABLISHED):
					print "Connection with " + destination + " established"
			else:
				print "Local node Found.. Not Connecting."
				pass		
	def run(self):	
		p = Process(target=self.create_server, args=())
		q = Process(target=self.connect_to_nodes, args=())
		p.start()
		q.start()
		p.join()
		q.join()
Start = MainNode()
Start.run()
"""
node_connector = Connect_to_nodes()
node.connector.connect_to_nodes()
"""

"""
Client: (ver)0x06, (null)0x00, (request)0x08, (params)destination,ip,port, (null)0x00
	
	
Server: (SOCKS6_OKAY)0x01, (SOCKS6_AUTH)0x00, (okay)0x01, (store-data, then success)0x03, (established)0x09	
"""
