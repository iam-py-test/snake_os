import os
import bcrypt
import json
import getpass
import sys
import requests

#main data

version = 0.2
hasloadedbefore = os.path.exists("config.snakeos.json")
configdata = {}
loginf = None

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
		


def os_cmd():
	global configdata
	try:
		while True:
			cmd = input("")
			parsecmd(cmd)
	except Exception as err:
		print(err)

def login():
	global configdata
	global hasloadedbefore
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
		os_cmd()
	else:
		configdata = json.loads(open("config.snakeos.json").read())
		print("----- SnakeOS -----")
		print("Please login: ")
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