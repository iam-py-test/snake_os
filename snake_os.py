import os
import json
import getpass
import sys
import time
import socket
import datetime

try:
	import requests
	import bcrypt
	import pytz
except:
	import subprocess
	devnull = open(os.devnull, 'wb')
	subprocess.Popen(sys.executable + " -m pip install requests", stdout=devnull, stderr=devnull)
	subprocess.Popen(sys.executable + " -m pip install bcrypt", stdout=devnull, stderr=devnull)
	subprocess.Popen(sys.executable + " -m pip install pytz", stdout=devnull, stderr=devnull)
	time.sleep(5)
	try:
		import bcrypt
		import requests
		import pytz
	except Exception as err:
		print(err)
		print("Required packages installed. Rebooting... ")
		subprocess.run([sys.executable, " ".join(sys.argv)],shell=True)
		sys.exit()
	


#main data

version = 0.3
hasloadedbefore = os.path.exists("config.snakeos.json")
configdata = {}
loginf = None
boottime = 0
bboottime = 0
aboottime = 0

#main functions

def parsecmd(cmd):
	global hasloadedbefore
	if cmd == "getuser":
		print(configdata["auth"]["username"])
	if cmd == "reset":
		print("Resetting SnakeOS will cause all data in SnakeOS to be deleted, and you will have to recreate your account.")
		confirm = input("Confirm: Do you want to reset SnakeOS? (y/n) ")
		if confirm == "y":
			os.remove("config.snakeos.json")
			hasloadedbefore = False
			loginf()
	if cmd == "shutdown":
		print("Shutting down SnakeOS")
		sys.exit()
	if cmd == "updates check":
		try:
			cversion = float(requests.get("https://raw.githubusercontent.com/iam-py-test/snake_os/main/version.txt").text)
			if cversion > version:
				print("Update available: You are running {}, however, {} is available".format(version,cversion))
			else:
				print("You are running the latest version of SnakeOS")
		except Exception as err:
			print("Failed to check for updates: {}".format(err))
	if cmd == "updates version":
		print("You are running SnakeOS version {}".format(version))
	if cmd == "updates install":
		try:
			cversion = float(requests.get("https://raw.githubusercontent.com/iam-py-test/snake_os/main/version.txt").text)
			print("This will erase any changes made to this file, but will leave your account intact")
			conti = input("Install version {}? (y/n)".format(cversion))
			if conti == "y":
				newversion = requests.get("https://raw.githubusercontent.com/iam-py-test/snake_os/main/snake_os.py").text
				cfile = open(__file__,"w")
				cfile.write(newversion)
				cfile.close()
				print("Updated to {}. Reboot to initialize ".format(cversion))
				
		except Exception as err:
			print("Failed to check for updates: {}".format(err))
	if cmd == "changepassword":
		confirmcha = input("Are you sure you want to change the account password? (y/n)")
		if confirmcha == 'y':
			currentpasswd = bcrypt.checkpw(getpass.getpass("Enter your current password: ").encode(),configdata["auth"]["password"].encode())
			if currentpasswd == True:
				newpass = getpass.getpass("Enter your new password: ")
				confirmpasswd = getpass.getpass("Confirm new password: ")
				if newpass == confirmpasswd:
					finalconfirm = input("Do you want to change the account password? (y/n)")
					if finalconfirm == 'y':
						configdata["auth"]["password"] = bcrypt.hashpw(newpass.encode(),bcrypt.gensalt(14)).decode()
						configf = open("config.snakeos.json","w")
						configf.write(json.dumps(configdata))
						configf.close()
				else:
					print("Passwords do not match")
			else:
				print("Password not valid. Please try again")
	if cmd.startswith("dnslookup "):
		try:
			domain = cmd.split(" ")[1]
			try:
				print(socket.gethostbyname(domain))
			except:
				print("Failed to preform DNS Lookup for {}".format(domain))
		except:
			print("Failed to preform dnslookup. Invalid command syntax")
	if cmd.startswith("requesturl "):
		try:
			url = cmd.split(" ")
			url.pop(0)
			url = " ".join(url)
			try:
				req = requests.get(url)
				print(req.text)
			except:
				print("Failed to load {}".format(url))
		except Exception as err:
			print("Failed to run requesturl: {}".format(err))
	if cmd == "reboot":
		import subprocess
		print("Shutting down...\n")
		subprocess.run([sys.executable, " ".join(sys.argv)],shell=True)
		sys.exit()
	# the time command and arguments
	if cmd == "time":
		print(datetime.datetime.now())
	if cmd.startswith("time -timezone "):
		try:
			timezone = cmd.split(" ")[2]
			print(datetime.datetime.now(pytz.timezone(timezone)))
		except Exception as err:
			if len(cmd.split(" ")) < 3:
				print("Invalid syntax for time -timezone")
			else:
				print(err)
	if cmd.startswith("time -day"):
		print(datetime.datetime.now().day)
	if cmd.startswith("time -hour"):
		print(datetime.datetime.now().hour)
	if cmd.startswith("time -utc"):
		print(datetime.datetime.utcnow())
	if cmd == "boottime":
		print("{}".format(boottime))


def os_cmd():
	global configdata
	try:
		while True:
			cmd = input("> ")
			parsecmd(cmd)
	except Exception as err:
		print(err)

def login():
	global configdata
	global hasloadedbefore
	global boottime
	if hasloadedbefore == False:	
		print("----- SnakeOS -----")
		print("Please create your account")
		configdata["auth"] = {}
		uname = input("Enter a username: ")
		configdata["auth"]["username"] = uname
		passwd = getpass.getpass("Enter a password for this account: ")
		hashed = bcrypt.hashpw(passwd.encode(),bcrypt.gensalt(14))
		configdata["auth"]["password"] = hashed.decode()
		configf = open("config.snakeos.json","w")
		configf.write(json.dumps(configdata))
		configf.close()
		boottime = time.time() - bboottime
		os_cmd()
	else:
		configdata = json.loads(open("config.snakeos.json").read())
		print("----- SnakeOS -----")
		print("Please login: ")
		boottime = time.time() - bboottime
		uname = input("Enter your username: ")
		if uname == configdata["auth"]["username"]:
			passwd = getpass.getpass().encode()
			if bcrypt.checkpw(passwd,configdata["auth"]["password"].encode()):
				print("Password valid")
				try:
					os_cmd()
				except:
					sys.exit()
			else:
				print("Password invalid")
		else:
			print("User does not exist")

#boot and pre-boot
loginf = login
print("Booting...")
print("Enter 'login' to login. Enter 'reset' to reset. Enter 'shutdown' to shutdown.")
options = input("Choice: ")
if options == "login":
	bboottime = time.time()
	login()
elif options == "reset":
	print("Resetting SnakeOS will cause all data to be lost")
	confirm = input("Reset anyway? (y/n)")
	if confirm == "y":
		try:
			os.remove("config.snakeos.json")
		except:
			pass
		hasloadedbefore = False
		login()
elif options == "shutdown":
	sys.exit()

input()