import socket
import ssl

class RDPEnumerator:
    def __init__(self, target, port=3389):
        self.target = target
        self.port = port
        self.results = []

    def enumerate(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            result = sock.connect_ex((self.target, self.port))
            
            if result == 0:
                self.results.append("RDP Port is OPEN (3389)")
                
                # Check for NLA / SSL support basic
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                try:
                    conn = ctx.wrap_socket(sock, server_hostname=self.target)
                    cert = conn.getpeercert(binary_form=True)
                    self.results.append("SSL/TLS wrapper accepted. NLA might be supported.")
                except Exception:
                    self.results.append("Could not negotiate SSL context.")
            else:
                self.results.append("RDP Port is CLOSED")
                
        except Exception as e:
            self.results.append(f"RDP Enumeration Error: {e}")
        
        return list(set(self.results))