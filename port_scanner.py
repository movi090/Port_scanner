import socket
import threading
from queue import Queue
import argparse
import time
from colorama import Fore, Style
from datetime import datetime
from tqdm import tqdm
import requests
import platform

# Настройки
TIMEOUT = 2
THREADS = 100
SHODAN_API_URL = "https://api.shodan.io/shodan/host/{}?key={}"

COLORS = {
    'OPEN': Fore.GREEN,
    'CLOSED': Fore.RED,
    'INFO': Fore.CYAN,
    'WARN': Fore.YELLOW
}

def parse_ports(ports_str):
    ports = set()
    parts = ports_str.split(',')
    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end+1))
        else:
            ports.add(int(part))
    return sorted(ports)

class BasicPortScanner:
    def __init__(self, target, ports, shodan_key=None):
        self.target = target
        self.ports = ports
        self.shodan_key = shodan_key
        self.results = []
        self.progress = None
        self.lock = threading.Lock()
        self.start_time = time.time()

    def get_service_name(self, port):
        try:
            return socket.getservbyport(port, 'tcp')
        except:
            return "unknown"

    def tcp_scan(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    service = self.get_service_name(port)
                    self.results.append((port, 'OPEN', service))
                s.close()
        except:
            pass

    def worker(self, queue):
        while not queue.empty():
            port = queue.get()
            self.tcp_scan(port)
            
            with self.lock:
                if self.progress:
                    self.progress.update(1)
            
            queue.task_done()

    def shodan_lookup(self):
        if not self.shodan_key:
            return

        try:
            response = requests.get(SHODAN_API_URL.format(self.target, self.shodan_key))
            if response.status_code == 200:
                data = response.json()
                print(f"\n{COLORS['INFO']}Shodan Results:{Style.RESET_ALL}")
                for item in data.get('data', []):
                    print(f"Port {item['port']}: {item.get('product', 'Unknown')}")
        except Exception as e:
            print(f"{COLORS['WARN']}Shodan Error: {e}{Style.RESET_ALL}")

    def run(self):
        queue = Queue()
        for port in self.ports:
            queue.put(port)

        print(f"\n{COLORS['INFO']}Scanning {self.target} ({len(self.ports)} ports){Style.RESET_ALL}")
        
        self.progress = tqdm(total=len(self.ports), desc="Progress", unit="port")

        threads = []
        for _ in range(THREADS):
            thread = threading.Thread(target=self.worker, args=(queue,))
            thread.start()
            threads.append(thread)

        queue.join()
        for thread in threads:
            thread.join()

        self.progress.close()
        self.shodan_lookup()

        self.results.sort()
        for port, status, service in self.results:
            color = COLORS.get(status, Fore.WHITE)
            print(f"{color}Port {port:5} {status:6} {service}{Style.RESET_ALL}")

        elapsed = time.time() - self.start_time
        print(f"\n{COLORS['INFO']}Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Basic TCP Port Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Ports (e.g. 1-1000,80,443)', default='1-1024')
    parser.add_argument('-s', '--shodan', help='Shodan API key')
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    scanner = BasicPortScanner(
        target=args.target,
        ports=ports,
        shodan_key=args.shodan
    )

    print(f"{COLORS['INFO']}=== TCP Port Scanner ==={Style.RESET_ALL}")
    print(f"{COLORS['INFO']}Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    
    scanner.run()

if __name__ == "__main__":
    main()