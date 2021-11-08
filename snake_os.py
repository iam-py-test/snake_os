import os
import json
import getpass
import sys
import time
import socket
import datetime
from urllib.parse import urlparse
import hashlib

# get boot time
try:
	bboottime = time.time()
except:
	bboottime = 0



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
	time.sleep(15)
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

version = 0.51
hasloadedbefore = os.path.exists("config.snakeos.json")
configdata = {}
loginf = None
boottime = 0
aboottime = 0
systemconfnames = ["System.systemname","System.Security.PIC.mode","System.Security.Software.verifyIntegrity","System.Software.integrityCheckDisabled","System.Security.PIC.disabled","System.Security.PIC.requires_evevation","System.Security.Firewall.denyrules","System.Security.Firewall.allowrules"]

#main functions

def readconf(confname):
	try:
		return configdata["conf"][confname]
	except:
		return None

def pic_enabled():
	if readconf("System.Security.PIC.disabled") == "1" and readconf("System.Security.PIC.requires_evevation") == "0":
		return False
	return True

def firewall_check(domain):
	try:
		mode = readconf("System.Security.Firewall.mode")
		denyrules = json.loads(readconf("System.Security.Firewall.denyrules"))
		allowrules = json.loads(readconf("System.Security.Firewall.allowrules"))
		if mode == "0":
			return True
		elif mode == "1":
			return domain not in denyrules
		elif mode == "2":
			return domain in allowrules
		else:
			return True
	except:
		pass

def parse_app(app):
	lines = app["code"].split("\n")
	appimports = []
	appvars = {}
	for line in lines:
		try:
			if line.startswith("#") or line == "":
				continue
			if line.startswith("IMPORT "):
				impname = line.split(" ")[1]
				appimports.append(impname)
			try:
				if line.split(".")[0] in appimports:
					if line.split(".")[0] == "output":
						if line.split(".")[1].split(" ")[0] == "print":
							text = line.split(".")[1].split(" ")
							text.pop(0)
							text = " ".join(text)
							if text.startswith("\""):
								text = text[1:-1]
								print(text)
						elif line.split(".")[1].split(" ")[0] == "printvar":
							text = line.split(".")[1].split(" ")
							text.pop(0)
							text = " ".join(text)
							try:
								print(appvars[text])
							except:
								print("SnakeOS script error: var {} not found".format(text))
			except:
				pass
			try:
				if line.startswith("setvar "):
					varname = line.split(" ")[1]
					varvalue = line.split(" ")
					varvalue.pop(0)
					varvalue.pop(0)
					varvalue = " ".join(varvalue)
					varvalue = varvalue.split("= ")
					varvalue.pop(0)
					varvalue = "= ".join(varvalue)
					varvalue = varvalue[1:-1]
					appvars[varname] = varvalue
			except Exception as err:
				print(err)

			
		except:
			pass

def parsecmd(cmd,runelevated=False):
	global hasloadedbefore
	global configdata
	
	
	# runelevated
	if cmd.startswith("runelevated "):
		if runelevated == True:
			newcmd = cmd.split(" ")
			newcmd.pop(0)
			parsecmd(" ".join(newcmd),runelevated=True)
			return None
		if readconf("System.Security.PIC.mode") != '0':
			passw = bcrypt.checkpw(getpass.getpass("Enter your password to request elevation: ").encode(),configdata["auth"]["password"].encode())
			if passw == False:
				print("runelevated: Incorrect password")
				return None
		newcmd = cmd.split(" ")
		newcmd.pop(0)
		parsecmd(" ".join(newcmd),runelevated=True)
		return None
	
	if cmd == "getuser":
		if runelevated == True:
			print("root")
		else:
			print(configdata["auth"]["username"])
	elif cmd == "reset":
		print("Resetting SnakeOS will cause all data in SnakeOS to be deleted, and you will have to recreate your account.")
		confirm = input("Confirm: Do you want to reset SnakeOS? (y/n) ")
		if confirm == "y":
			os.remove("config.snakeos.json")
			hasloadedbefore = False
			loginf()
	elif cmd == "shutdown":
		print("Shutting down SnakeOS")
		configf = open("config.snakeos.json","w")
		configf.write(json.dumps(configdata))
		configf.close()
		sys.exit()
	elif cmd == "updates check":
		try:
			cversion = float(requests.get("https://raw.githubusercontent.com/iam-py-test/snake_os/main/version.txt").text)
			if cversion > version:
				print("Update available: You are running {}, however, {} is available".format(version,cversion))
			else:
				print("You are running the latest version of SnakeOS")
		except Exception as err:
			print("Failed to check for updates: {}".format(err))
	elif cmd == "updates version":
		print("You are running SnakeOS version {}".format(version))
	elif cmd == "updates install":
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
	elif cmd == "changepassword":
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
	elif cmd.startswith("dnslookup "):
		try:
			domain = cmd.split(" ")[1]
			try:
				print(socket.gethostbyname(domain))
			except:
				print("Failed to preform DNS Lookup for {}".format(domain))
		except:
			print("Failed to preform dnslookup. Invalid command syntax")
	elif cmd.startswith("requesturl "):
		try:
			url = cmd.split(" ")
			url.pop(0)
			url = " ".join(url)
			domain = urlparse(url).netloc
			if firewall_check(domain) == False:
				print("Failed to load {}: Blocked by Firewall".format(url))
				return
			try:
				req = requests.get(url)
				print(req.text)
			except:
				print("Failed to load {}".format(url))
		except Exception as err:
			print("Failed to run requesturl: {}".format(err))
	elif cmd == "reboot":
		import subprocess
		print("Shutting down...\n")
		configf = open("config.snakeos.json","w")
		configf.write(json.dumps(configdata))
		configf.close()
		subprocess.run([sys.executable, " ".join(sys.argv)])
		sys.exit()
	# the time command and arguments
	elif cmd == "time":
		print(datetime.datetime.now())
	elif cmd.startswith("time -timezone "):
		try:
			timezone = cmd.split(" ")[2]
			print(datetime.datetime.now(pytz.timezone(timezone)))
		except Exception as err:
			if len(cmd.split(" ")) < 3:
				print("Invalid syntax for time -timezone")
			else:
				print(err)
	elif cmd.startswith("time -day"):
		print(datetime.datetime.now().day)
	elif cmd.startswith("time -hour"):
		print(datetime.datetime.now().hour)
	elif cmd.startswith("time -utc"):
		print(datetime.datetime.utcnow())
	elif cmd == "boottime":
		print("{}".format(boottime))
	# system config
	elif cmd.startswith("sysconf "):
		try:
			if configdata["conf"] == None:
				configdata["conf"] = {}
		except:
			configdata["conf"] = {}
		if cmd.startswith("sysconf read "):
			try:
				confname = cmd.split(" ")[2]
				try:
					print(configdata["conf"][confname])
				except:
					print("{} not found".format(confname))
			except:
				print("Invalid command syntax for sysconf")
		elif cmd.startswith("sysconf write "):
			if runelevated == True or pic_enabled() == False:
				try:
					confname = cmd.split(" ")[2]
					confvalue = cmd.split(" ")[3]
					if confname.startswith("System.Security.PIC."):
						if input("Are you are you want to modify PIC settings? (y/n)") != "y":
							return None
					configdata["conf"][confname] = confvalue
					configf = open("config.snakeos.json","w")
					configf.write(json.dumps(configdata))
					configf.close()
				except Exception as err:
					print("Invalid command syntax for sysconf: {}".format(err))
			else:
				print("Access denied: Please retry with elevation")
		elif cmd.startswith("sysconf delete "):
			if runelevated == True or pic_enabled() == False:
				try:
					confname = cmd.split(" ")[2]
					if confname in systemconfnames:
						print("Can not delete part of critical system configuration: {}".format(confname))
					else:
						del configdata["conf"][confname]
					configf = open("config.snakeos.json","w")
					configf.write(json.dumps(configdata))
					configf.close()
				except:
					print("Invalid command syntax for sysconf")
			else:
				print("Access denied: Please retry with elevation")
		elif cmd == "sysconf listconf":
			try:
				for config_part in configdata["conf"]:
					print("{}:{}".format(config_part,configdata["conf"][config_part]))
			except Exception as err:
				print("Failed to list: {}".format(err))
		else:
			print("sysconf: Command not found")
	elif cmd == "localip":
		print(socket.gethostbyname(socket.gethostname()))
	elif cmd.startswith("software "):
		if cmd.startswith("software install "):
			if runelevated == True or pic_enabled() == False:
				try:
					softname = cmd.split(" ")[2]
					softmanifest = json.loads(requests.get("https://raw.githubusercontent.com/iam-py-test/snake_os/main/.software/config.json").text)
					print("Are you sure you want to install '{}'? ".format(softname))
					print("Description: {}".format(softmanifest[softname]["desc"]))
					if input("Type 'y' to install: ") == "y":
						content = requests.get(softmanifest[softname]["url"]).text
						try:
							if configdata["software"] == None:
								configdata["software"] = {}
						except:
							configdata["software"] = {}
						configdata["software"][softname] = {"desc":softmanifest[softname]["desc"],"code":content,"version":softmanifest[softname]["version"],"integrity":hashlib.sha512(content.encode()).hexdigest()}
						configf = open("config.snakeos.json","w")
						configf.write(json.dumps(configdata))
						configf.close()
				except Exception as err:
					print("Install error: {}".format(err))
			else:
				print("Access denied: Please retry with elevation")
		elif cmd.startswith("software run "):
			try:
				softname = cmd.split(" ")[2]
				integrityneeded = readconf("System.Security.Software.verifyIntegrity") == "1" or readconf("System.Software.integrityCheckDisabled") != "1"
				try:
					if configdata["software"] == None:
							configdata["software"] = {}
				except:
						configdata["software"] = {}
				try:
					soft = configdata["software"][softname]
					contenthash = hashlib.sha512(soft["code"].encode()).hexdigest()
					if contenthash == soft["integrity"] or integrityneeded == False:
						parse_app(soft)
					else:
						print("Integrity of '{}' could not be verified".format(softname))
						if input("Reinstall? (y/n) ") == "y":
							parsecmd("runelevated software install {}".format(softname))
				except Exception as err:
					print("{} not installed: {}".format(softname,err))
			except:
				pass
		elif cmd.startswith("software uninstall "):
			if runelevated == True or pic_enabled() == False:
				try:
					softname = cmd.split(" ")[2]
					print("Are you sure you want to uninstall '{}'? ".format(softname))
					if input("Type 'y' to uninstall: ") == "y":
						try:
							if configdata["software"] == None:
								configdata["software"] = {}
						except:
							configdata["software"] = {}
						del configdata["software"][softname]
						configf = open("config.snakeos.json","w")
						configf.write(json.dumps(configdata))
						configf.close()
				except Exception as err:
					print("Uninstall error: {}".format(err))
			else:
				print("Access denied: Please retry with elevation")
		elif cmd == "software update":
			try:
				softmanifest = json.loads(requests.get("https://raw.githubusercontent.com/iam-py-test/snake_os/main/.software/config.json").text)
				for softname in softmanifest:
					try:
						if configdata["software"][softname]["version"] < softmanifest[softname]["version"]:
							print("Updating {} from version {} to {}".format(softname,configdata["software"][softname]["version"],softmanifest[softname]["version"]))
							content = requests.get(softmanifest[softname]["url"]).text
							configdata["software"][softname] = {"desc":softmanifest[softname]["desc"],"code":content,"version":softmanifest[softname]["version"],"integrity":hashlib.sha512(content.encode()).hexdigest()}
					except:
						continue
				configf = open("config.snakeos.json","w")
				configf.write(json.dumps(configdata))
				configf.close()
			except:
				print("Update error")
	elif cmd.startswith("alias "):
		if cmd.startswith("alias create "):
			try:
				alias = cmd.split(" ")[2]
				cmdtorun = cmd.split(" ")
				cmdtorun.pop(0)
				cmdtorun.pop(0)
				cmdtorun.pop(0)
				cmdtorun = " ".join(cmdtorun)
				try:
					if configdata["alias"] == None:
						configdata["alias"] = {}
				except:
					configdata["alias"] = {}
				configdata["alias"][alias] = cmdtorun
				configf = open("config.snakeos.json","w")
				configf.write(json.dumps(configdata))
				configf.close()
			except Exception as err:
				print("Failed to create alias: {}".format(err))
		elif cmd.startswith("alias delete "):
			try:
				alias = cmd.split(" ")[2]
				try:
					if configdata["alias"] == None:
						configdata["alias"] = {}
				except:
					configdata["alias"] = {}
				del configdata["alias"][alias]
				configf = open("config.snakeos.json","w")
				configf.write(json.dumps(configdata))
				configf.close()
			except Exception as err:
				print("Failed to delete alias: {}".format(err))
	elif cmd.startswith("hashtools"):
		try:
			text = cmd.split(" ")
			text.pop(0)
			text.pop(0)
			text = " ".join(text)
			cmdname = cmd.split(" ")[1]
			if cmdname == "sha512":
				print(hashlib.sha512(text.encode()).hexdigest())
			elif cmdname ==  "sha384":
				print(hashlib.sha384(text.encode()).hexdigest())
			elif cmdname == "sha256":
				print(hashlib.sha256(text.encode()).hexdigest())
			elif cmdname == "sha224":
				print(hashlib.sha224(text.encode()).hexdigest())
			elif cmdname == "sha1":
				print(hashlib.sha1(text.encode()).hexdigest())
			elif cmdname == "md5":
				print(hashlib.md5(text.encode()).hexdigest())
			elif cmdname == "help":
				print("hashtools sha512 [string]: Returns the sha512 digest of [string]")
				print("hashtools sha384 [string]: Returns the sha384 digest of [string]")
				print("hashtools sha256 [string]: Returns the sha256 digest of [string]")
				print("hashtools sha224 [string]: Returns the sha224 digest of [string]")
				print("hashtools sha1 [string]: Returns the sha1 digest of [string]")
				print("hashtools md5 [string]: Returns the md5 digest of [string]")
				print("hashtools help: Displays this help screen")
			else:
				print("Hashtools: {} is not a valid hashtool".format(cmdname))
		except Exception as err:
			print("Hashtools error: {}".format(err))
	elif cmd.startswith("math "):
		try:
			mr = cmd.split(" ")
			mr.pop(0)
			mr = " ".join(mr)
			#parsing mathematical expressions - https://stackoverflow.com/a/9558001
			import ast
			import operator as op

			# supported operators
			operators = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
             ast.Div: op.truediv, ast.Pow: op.pow, ast.BitXor: op.xor,
             ast.USub: op.neg}

			def eval_expr(expr):
				"""
				>>> eval_expr('2^6')
				4
				>>> eval_expr('2**6')
				64
				>>> eval_expr('1 + 2*3**(4^5) / (6 + -7)')
				-5.0
				"""
				return eval_(ast.parse(expr, mode='eval').body)

			def eval_(node):
				if isinstance(node, ast.Num): # <number>
					return node.n
				elif isinstance(node, ast.BinOp): # <left> <operator> <right>
					return operators[type(node.op)](eval_(node.left), eval_(node.right))
				elif isinstance(node, ast.UnaryOp): # <operator> <operand> e.g., -1
					return operators[type(node.op)](eval_(node.operand))
				else:
					raise TypeError(node)
			print(eval_expr(mr))
		except Exception as err:
			print(err)
	elif cmd.startswith("eval "):
		try:
			newcmd = cmd.split(" ")
			newcmd.pop(0)
			newcmd = " ".join(newcmd)
			parsecmd(newcmd,runelevated=False)
		except Exception as err:
			print(err)
	elif cmd.startswith("echo "):
		try:
			toecho = cmd.split(" ")
			toecho.pop(0)
			toecho = " ".join(toecho)
			print(toecho)
		except Exception as err:
			print(err)
	elif cmd == "netdig":
		print("Running network diagnostic...")
		try:
			if socket.gethostbyname("example.com") == "0.0.0.0":
				raise Exception("Example.com === 0.0.0.0")
			else:
				print("DNS resolves successfully ")
		except Exception as err:
			print("Error in resolving DNS: {}".format(err))
		try:
			requests.get("http://example.com")
		except Exception as err:
			print("Error in contacting website: {}".format(err))
		else:
			print("Able to contact websites")
		try:
			requests.get("https://example.com")
		except Exception as err:
			print("Unable to connect to a website over TLS: {}".format(err))
		else:
			print("Able to connect to websites over TLS")
		try:
			req = requests.get("https://raw.githubusercontent.com/iam-py-test/snake_os/main/version.txt")
			if req.status_code != 200:
				raise Exception("Not found?")
		except Exception as err:
			print("Error in contacting server: {}".format(err))
		else:
			print("Able to contact server")
	elif cmd.startswith("firewall "):
		if cmd.startswith("firewall listrules"):
			try:
				denyrules = json.loads(readconf("System.Security.Firewall.denyrules"))
			except:
				print("No deny rules")
			else:
				if denyrules == []:
					print("No deny rules")
				else:
					print("Denied domains/ips: ")
					for rule in denyrules:
						print(rule)
			try:
				allowrules = json.loads(readconf("System.Security.Firewall.allowrules"))
			except:
				print("No allow rules")
			else:
				if denyrules == []:
					print("No allow rules")
				else:
					print("Allowed domains/ips: ")
					for rule in allowrules:
						print(rule)
		elif cmd.startswith("firewall allow "):
			if runelevated == True:
				domain = cmd.split(" ")[2]
				try:
					allowrules = json.loads(readconf("System.Security.Firewall.allowrules"))
				except:
					allowrules = []
				allowrules.append(domain)
				configdata["conf"]["System.Security.Firewall.allowrules"] = json.dumps(allowrules)
			else:
				print("Access denied")
		elif cmd.startswith("firewall deny "):
			if runelevated == True:
				domain = cmd.split(" ")[2]
				try:
					denyrules = json.loads(readconf("System.Security.Firewall.denyrules"))
				except:
					denyrules = []
				denyrules.append(domain)
				configdata["conf"]["System.Security.Firewall.denyrules"] = json.dumps(denyrules)
			else:
				print("Access denied")
		elif cmd == ("firewall mode"):
			print(readconf("System.Security.Firewall.mode"))
		elif cmd.startswith("firewall mode "):
			if runelevated == True:
				configdata["conf"]["System.Security.Firewall.mode"] = cmd.split(" ")[2]
				configf = open("config.snakeos.json","w")
				configf.write(json.dumps(configdata))
				configf.close()
			else:
				print("Access denied")
		elif cmd.startswith("firewall denyrules.remove "):
			if runelevated == True:
				domain = cmd.split(" ")[2]
				try:
					denyrules = json.loads(readconf("System.Security.Firewall.denyrules"))
				except:
					denyrules = []
				denyrules.remove(domain)
				configdata["conf"]["System.Security.Firewall.denyrules"] = json.dumps(denyrules)
			else:
				print("Access denied")
		elif cmd.startswith("firewall allowrules.remove "):
			if runelevated == True:
				domain = cmd.split(" ")[2]
				try:
					allowrules = json.loads(readconf("System.Security.Firewall.allowrules"))
				except:
					allowrules = []
				allowrules.remove(domain)
				configdata["conf"]["System.Security.Firewall.allowrules"] = json.dumps(allowrules)
			else:
				print("Access denied")
			
	elif cmd.startswith("base64 "):
		if cmd.startswith("base64 encode "):
			try:
				str = cmd.split(" ")
				str.pop(0)
				str.pop(0)
				str = " ".join(str)
				import base64
				print(base64.b64encode(str.encode()).decode())
			except Exception as err:
				print(err)
		elif cmd.startswith("base64 decode "):
			try:
				str = cmd.split(" ")
				str.pop(0)
				str.pop(0)
				str = " ".join(str)
				import base64
				print(base64.b64decode(str.encode()).decode())
			except Exception as err:
				print(err)
		else:
			print("base64: Command not found")
	elif cmd == "randomnumb":
		try:
			import random
			print(random.randrange(0,random.choice([20,random.randrange(30,9000),random.randrange(100,90000)])))
		except Exception as err:
			print(err)
	elif cmd.startswith("runtimes "):
		try:
			times = int(cmd.split(" ")[1])
			d = 0
			cmd2 = cmd.split(" ")
			cmd2.pop(0)
			cmd2.pop(0)
			cmd2 = " ".join(cmd2)
			while d < times:
				parsecmd(cmd2)
				d += 1
		except Exception as err:
			print(err)
	else:
		try:
			parsecmd(configdata["alias"][cmd])
			return None
		except Exception as err:
			print("Command not found: {}".format(cmd))


def os_cmd():
	global configdata
	try:
		while True:
			cmd = input("> ")
			try:
				parsecmd(cmd)
			except KeyboardInterrupt as err:
				pass
	except Exception as err:
		print(err)

def login():
	global configdata
	global hasloadedbefore
	global boottime
	try:
		if hasloadedbefore == False:	
			print("----- SnakeOS -----")
			print("Please create your account")
			configdata["auth"] = {}
			configdata["conf"] = {"System.Security.PIC.mode":"1","System.Security.Software.verifyIntegrity":"1","System.Security.Firewall.mode":"1","System.Security.Firewall.allowrules":"[]","System.Security.Firewall.denyrules":"[]"}
			configdata["software"] = {}
			configdata["alias"] = {}
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
	except Exception as err:
		print("Failed to boot: {}".format(err))
		print("If this error persists, try resetting via the boot menu")

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