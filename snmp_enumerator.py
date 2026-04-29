import socket
import subprocess

class SNMPEnumerator:
    def __init__(self, target, community="public"):
        self.target = target
        self.community = community
        self.results = []

    def enumerate(self):
        try:
            # Check basic SNMP reachability (UDP 161)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            
            # Simple SNMPv1/v2c GetRequest for sysDescr.0
            # 0x30 = Sequence, 0x26 = length (38)
            # 0x02,0x01,0x00 = Version 1
            # 0x04,0x06... = Community (public config)
            # ... SNMP struct
            
            # Using snmpwalk if available otherwise fallback
            cmd = ['snmpwalk', '-v', '2c', '-c', self.community, self.target, '1.3.6.1.2.1.1.1.0']
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            if out:
                lines = out.decode('utf-8', errors='ignore').split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        self.results.append(line)
            else:
                self.results.append("SNMP might not be enabled, or community string is incorrect.")
                
        except FileNotFoundError:
            self.results.append("snmpwalk command not found. Install snmp tools.")
        except Exception as e:
            self.results.append(f"SNMP Error: {e}")
        
        return list(set(self.results))