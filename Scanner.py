pip install requests python-whois
import socket
import requests
import whois
import threading
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin
def port_scanner(target_ip, port_range=(1, 1024)):
    print(f"Scanning ports on {target_ip}...\n")
    open_ports = []

    def scan(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"[OPEN] Port {port}")
                open_ports.append(port)
            sock.close()
        except:
            pass

    threads = []
    for port in range(port_range[0], port_range[1]):
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if not open_ports:
        print("No open ports found.")
    return open_ports
  def brute_force_http(url, usernames, passwords):
    print(f"\nBrute-forcing: {url}")
    for user in usernames:
        for pwd in passwords:
            response = requests.get(url, auth=HTTPBasicAuth(user, pwd))
            print(f"Trying {user}:{pwd} → Status {response.status_code}")
            if response.status_code == 200:
                print(f"✅ Found: {user}:{pwd}")
                return user, pwd
    print("❌ No valid credentials found.")
    return None
    def whois_lookup(domain):
    print(f"Looking up domain: {domain}")
    try:
        info = whois.whois(domain)
        print(f"Registrar: {info.registrar}")
        print(f"Creation Date: {info.creation_date}")
        print(f"Expiration Date: {info.expiration_date}")
        print(f"Name Servers: {info.name_servers}")
    except Exception as e:
        print(f"Error: {e}")
      def subdomain_scanner(domain, wordlist):
    print(f"\nScanning subdomains for {domain}")
    found = []
    for word in wordlist:
        sub = f"{word.strip()}.{domain}"
        try:
            socket.gethostbyname(sub)
            print(f"[FOUND] {sub}")
            found.append(sub)
        except:
            pass
    return found
    # Test 1: Port Scanner
port_scanner("scanme.nmap.org", (79, 83))  # Use smaller range to test

# Test 2: HTTP Brute Forcer
brute_force_http("http://httpbin.org/basic-auth/admin/admin",
                 usernames=["admin", "user"],
                 passwords=["admin", "1234"])

# Test 3: WHOIS
whois_lookup("example.com")

# Test 4: Subdomain Scanner
wordlist = ["www", "mail", "ftp", "admin"]
subdomain_scanner("example.com", wordlist)
brute_force_http("http://httpbin.org/basic-auth/admin/admin",
                 usernames=["admin", "user"],
                 passwords=["admin", "1234"])
whois_lookup("example.com")
subdomain_scanner("example.com", ["www", "ftp", "admin", "mail"])
