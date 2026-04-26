import socket
import logging
import concurrent.futures
# test
class PortScanner:
    def __init__(self, target, ports=None):
        self.target = target
        if ports is None:
            # Default common AD and enumeration ports
            self.ports = [21, 22, 23, 25, 53, 80, 88, 111, 135, 139, 389, 443, 445, 464, 593, 636, 1433, 3268, 3269, 3306, 3389, 5985, 5986, 8080]
        else:
            self.ports = ports
            
        self.logger = logging.getLogger('PortScanner')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def grab_banner(self, ip, port, timeout=2.0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                
                # If HTTP/HTTPs, send a basic GET request to fetch the Server banner
                if port in [80, 443, 8080, 8443, 8000]:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                
                # Process HTTP headers for Server name
                if banner.startswith("HTTP"):
                    for line in banner.split('\n'):
                        if line.lower().startswith("server:"):
                            return line.replace('\r', '').strip()
                    return "HTTP Service (No Server Header)"
                
                return banner.split('\n')[0].replace('\r', '')[:100] if banner else "Open (No Banner)"
        except Exception:
            return "Open (No Banner)"

    def scan_port(self, port, timeout=0.5):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout) # Faster timeout for initial open check
                result = s.connect_ex((self.target, port))
                if result == 0:
                    banner = self.grab_banner(self.target, port)
                    return port, banner
        except Exception:
            pass
        return None

    def scan_all(self, max_workers=100, connect_timeout=0.5, verbose=False):
        self.logger.info(f"Starting port scan on {self.target}...")
        results = []
        
        # Determine IP natively
        try:
            resolved_ip = socket.gethostbyname(self.target)
            self.target = resolved_ip
        except Exception as e:
            self.logger.error(f"Failed to resolve target {self.target}: {e}")
            return results

        print(f"[*] Scanning {len(self.ports)} ports on {self.target} (workers: {max_workers})...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.scan_port, port, connect_timeout) for port in self.ports]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    port, banner = res
                    if verbose:
                        print(f" [LIVE] Found Port: {str(port).ljust(5)}  |  {banner}")
                    results.append({'port': port, 'banner': banner})
                    
        # Sort sequentially
        results = sorted(results, key=lambda x: x['port'])
        return results
