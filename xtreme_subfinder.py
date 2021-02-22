#!/usr/bin/env python3

import subprocess
from termcolor import colored
import os
import threading
import argparse
import signal,sys
import re
import datetime

#devnull
FNULL = open(os.devnull, 'w')

def banner(url):


	w ="""

  	   _  ____                                         __    _____           __         
	  | |/ / /_________  ____ ___  ___     _______  __/ /_  / __(_)___  ____/ /__  _____
	  |   / __/ ___/ _ \/ __ `__ \/ _ \   / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
	 /   / /_/ /  /  __/ / / / / /  __/  (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
	/_/|_\__/_/   \___/_/ /_/ /_/\___/  /____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/     
	"""                                                                                    



 
	x = "		+-----------------------------------------------------------------------------+"     
	y = "				           			~~Twitter: Killeroo7p && Tanujbaware\n\n"

	z = """

	URL     : """+url+"""
	Time    : """+str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))+"""

	"""

	print(colored(w,'blue'))
	print(colored(x,'red'))
	print(colored(y,'green'))
	print(colored(z,'blue'))

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u','--url',dest='url',required=True,help="Specify URL")
	parser.add_argument('-o','--output',dest='output',help="Output Location")
	parser.add_argument('-a','--include amass',dest='i_amass',action='store_true',help="will include amass")
	args = parser.parse_args()
	return args


def signal_handler(signal, frame):
  print(colored("\n\nExitting.... BYE BYE\n","cyan"))
  sys.exit(0)


def create_unique_directory(url,location):
	directory = f"subs_"+url+"{}"
	counter = 0
	while os.path.exists(f"{location}{directory.format(counter)}"):
	    counter += 1
	directory = directory.format(counter)
	os.mkdir(f"{location}/{directory}")
	os.chdir(f"{location}/{directory}")
	return f"{location}/{directory}"

def filter_duplicate_domains(x):
  return list(dict.fromkeys(x))

def assetfinder(url,location):
	print(colored("[+] Scanning For Subdomains with AssetFinder",'green'))
	asset_cmd = f"assetfinder {url} --subs-only |tee {location}/assetfinder_subs_file"
	#with open(os.devnull,'w') as devnull:
	subprocess.call(asset_cmd,shell=True,stdout=False)
	
	print(colored("[+] AssetFinder Scanning Completed",'yellow'))


def amass(url,location):
	print(colored("[+] Scanning For Subdomains with Amass",'green'))
	amass_cmd = f"amass enum -d {url} -o {location}/amass_subs_file"
	#with open(os.devnull,'w') as devnull:
	subprocess.call(amass_cmd,shell=True,stdout=FNULL,stderr=FNULL)
	print(colored("[+] Amass Scanning Completed",'yellow'))


def subfinder(url,location): 
	print(colored("[+] Scanning For Subdomains with Subfinder",'green'))
	subfinder_cmd = f"subfinder -d {url} -o {location}/subfinder_subs_file"
	#with open(os.devnull,'w') as devnull:
	subprocess.call(subfinder_cmd,shell=True,stdout=FNULL,stderr=FNULL)
	print(colored("[+] Subfinder Scanning Completed",'yellow'))


def filter_subs():
		all_subs = []
		
		with open ('assetfinder_subs_file','r') as assetfinder_subs:
			for line in assetfinder_subs:
				all_subs.append(line)
		if (get_args().i_amass==True):
			with open ('amass_subs_file','r') as amass_subs:
				for line in amass_subs:
					all_subs.append(line)

		with open ('subfinder_subs_file','r') as subfinder_subs:
			for line in subfinder_subs:
				all_subs.append(line)

		filtered = filter_duplicate_domains(all_subs)
		with open ('subdomains.txt','w+') as all_subs_file:
			for line in filtered:
				all_subs_file.write(line)

		print(colored("[+] Removed Duplicate Domains",'yellow'))
		# print(colored("[+] Subdomains Saved To: ",'white')+colored(os.getcwd()+"/subdomains.txt","cyan"))

#		os.remove('sublister_subs_file')
		os.remove('assetfinder_subs_file')
		if (get_args().i_amass==True):
			os.remove('amass_subs_file')
		os.remove('subfinder_subs_file')


def http_probe():
	file = "httprobe_subdomains.txt"
	print(colored("[+] Started HttProbe on subdomains.txt","green"))
	cmd = "cat subdomains.txt | httprobe > " + file
	# with open(os.devnull,'w') as devnull:
	subprocess.call(cmd,shell=True)

	print(colored("[+] Httprobe Completed",'yellow'))
	# print(colored("[+] HttpProbe Subdomains Saved To: ",'white')+colored(os.getcwd()+"/"+file,"blue"))


def main():

	url = get_args().url
	banner(url)

	if not bool(get_args().output):
		output=os.getcwd()
	else:
		output=get_args().output


	if "http" in url:
		print("Enter URL in format domain.tld")
		exit(0)

	# directory=create_unique_directory(url,output)
	directory=output=os.getcwd()
	signal.signal(signal.SIGINT, signal_handler)

	t1 = threading.Thread(target=assetfinder,name="t_assetfinder",args=([url,directory]))
	t1.start()

	if (get_args().i_amass==True):
		t2 = threading.Thread(target=amass,name="t_amss",args=([url,directory]))
		t2.start()
	else:
		print(colored("[note] [-] Amass Scanning is not Included",'cyan'))	

	t3 = threading.Thread(target=subfinder,name="t_subfinder",args=([url,directory]))
	t3.start()

	t1.join()
	if (get_args().i_amass==True):
		t2.join()
	t3.join()

	filter_subs()
	http_probe()

	print(colored("\n[+] Subdomain Scanning Completed",'cyan'))
	print(colored(f"\n[+] Output Saved to {directory}",'yellow'))


main()