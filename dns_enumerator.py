import socket
import subprocess
import os
import platform

class DNSEnumerator:
    def __init__(self, target):
        self.target = target
        self.results = []

    def enumerate(self):
        try:
            # Basic A record resolution
            ip = socket.gethostbyname(self.target)
            self.results.append(f"A Record: {self.target} -> {ip}")
            
            # Simple check via nslookup (works on Windows/Linux)
            cmd = ['nslookup', '-type=any', self.target]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            if out:
                lines = out.decode('utf-8', errors='ignore').split('\n')
                for line in lines:
                    line = line.strip()
                    if line and "Server:" not in line and "Address:" not in line:
                        self.results.append(line)
                        
            # Basic zone transfer attempt using dig
            if platform.system() != "Windows":
                cmd_axfr = ['dig', f'@{self.target}', self.target, 'AXFR']
                proc_axfr = subprocess.Popen(cmd_axfr, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out_axfr, _ = proc_axfr.communicate()
                if b"Transfer failed" not in out_axfr and b"failed" not in out_axfr:
                    self.results.append(f"Possible Zone Transfer Success:\n{out_axfr.decode('utf-8', errors='ignore')}")

        except Exception as e:
            self.results.append(f"DNS Resolution Error: {e}")
        
        return list(set(self.results))
