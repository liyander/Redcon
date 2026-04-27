import logging
import ssl
import socket
import urllib.request
import urllib.error
from datetime import datetime

class HTTPSEnumerator:
    def __init__(self, target, port=443, timeout=10):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.ssl_context = None
        self.cert_info = None

        # Configure logging
        self.logger = logging.getLogger('HTTPSEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def connect(self):
        """Establish HTTPS connection and retrieve certificate."""
        self.logger.info(f"Connecting to {self.target}:{self.port} over HTTPS...")
        try:
            # Create SSL context
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with self.ssl_context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    self.cert_info = ssock.getpeercert()
                    self.logger.info("Successfully retrieved SSL/TLS certificate.")
                    return True
        except socket.timeout:
            self.logger.error(f"Connection timeout to {self.target}:{self.port}")
            return False
        except ssl.SSLError as e:
            self.logger.error(f"SSL Error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Connection Error: {e}")
            return False

    def get_certificate_info(self):
        """Extract and return detailed certificate information."""
        if not self.cert_info:
            self.logger.error("No certificate information available.")
            return {}

        self.logger.info("Extracting certificate information...")
        cert_data = {}
        try:
            # Subject
            subject = dict(x[0] for x in self.cert_info.get('subject', []))
            cert_data['Subject'] = subject.get('commonName', 'N/A')

            # Issuer
            issuer = dict(x[0] for x in self.cert_info.get('issuer', []))
            cert_data['Issuer'] = issuer.get('commonName', 'N/A')

            # Validity
            cert_data['Valid From'] = self.cert_info.get('notBefore', 'N/A')
            cert_data['Valid Until'] = self.cert_info.get('notAfter', 'N/A')

            # Check if expired
            not_after = self.cert_info.get('notAfter', '')
            if not_after:
                expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                is_expired = expire_date < datetime.now()
                cert_data['Is Expired'] = 'YES (VULNERABLE!)' if is_expired else 'NO'

            # Subject Alternative Names (SAN)
            san_list = []
            for san in self.cert_info.get('subjectAltName', []):
                if san[0] == 'DNS':
                    san_list.append(san[1])
            cert_data['Subject Alt Names'] = ', '.join(san_list) if san_list else 'None'

            # Serial Number
            cert_data['Serial Number'] = self.cert_info.get('serialNumber', 'N/A')

            # Version
            cert_data['Version'] = self.cert_info.get('version', 'N/A')

            self.logger.info(f"Certificate Subject: {cert_data['Subject']}")
            self.logger.info(f"Certificate Issuer: {cert_data['Issuer']}")

            return cert_data
        except Exception as e:
            self.logger.error(f"Error extracting certificate info: {e}")
            return cert_data

    def check_certificate_vulnerabilities(self):
        """Check for common SSL/TLS certificate vulnerabilities."""
        if not self.cert_info:
            self.logger.error("No certificate information available.")
            return {}

        self.logger.info("Checking for certificate vulnerabilities...")
        vulnerabilities = {}

        try:
            # Check for self-signed certificate
            subject = dict(x[0] for x in self.cert_info.get('subject', []))
            issuer = dict(x[0] for x in self.cert_info.get('issuer', []))

            if subject.get('commonName') == issuer.get('commonName'):
                vulnerabilities['Self-Signed'] = 'YES (VULNERABLE!)'
                self.logger.warning("Certificate is self-signed!")

            # Check if expired
            not_after = self.cert_info.get('notAfter', '')
            if not_after:
                expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                if expire_date < datetime.now():
                    vulnerabilities['Expired'] = 'YES (VULNERABLE!)'
                    self.logger.warning("Certificate is expired!")

            # Check for wildcard certificate
            subject_cn = subject.get('commonName', '')
            if subject_cn.startswith('*.'):
                vulnerabilities['Wildcard Certificate'] = 'YES (May be risky)'
                self.logger.warning(f"Wildcard certificate detected: {subject_cn}")

            # Check for weak issuer
            issuer_cn = issuer.get('commonName', '')
            weak_issuers = ['self', 'internal', 'test']
            if any(weak in issuer_cn.lower() for weak in weak_issuers):
                vulnerabilities['Weak Issuer'] = f'YES - {issuer_cn}'
                self.logger.warning(f"Potentially weak issuer: {issuer_cn}")

            if not vulnerabilities:
                vulnerabilities['No Major Issues'] = 'Checked'
                self.logger.info("No major certificate vulnerabilities detected.")

            return vulnerabilities
        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities: {e}")
            return vulnerabilities

    def get_server_banner(self):
        """Retrieve the server banner and HTTP headers."""
        self.logger.info(f"Attempting to grab server banner from {self.target}:{self.port}...")
        banner_info = {}

        try:
            url = f"https://{self.target}:{self.port}/"

            # Create request with custom headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')

            # Disable SSL verification for self-signed certs
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            try:
                response = urllib.request.urlopen(req, context=ssl_context, timeout=self.timeout)

                # Extract relevant headers
                headers = response.headers
                banner_info['Server'] = headers.get('Server', 'Not disclosed')
                banner_info['Content-Type'] = headers.get('Content-Type', 'N/A')
                banner_info['X-Powered-By'] = headers.get('X-Powered-By', 'N/A')
                banner_info['X-AspNet-Version'] = headers.get('X-AspNet-Version', 'N/A')
                banner_info['Apache-Version'] = headers.get('Apache', 'N/A')

                self.logger.info(f"Server Banner: {banner_info.get('Server', 'Unknown')}")
                return banner_info
            except urllib.error.HTTPError as e:
                # Even with HTTP errors, we can get headers
                headers = e.headers
                banner_info['Server'] = headers.get('Server', 'Not disclosed')
                banner_info['Content-Type'] = headers.get('Content-Type', 'N/A')
                self.logger.info(f"Server Banner (from error response): {banner_info.get('Server', 'Unknown')}")
                return banner_info
        except socket.timeout:
            self.logger.error(f"Timeout while retrieving server banner")
            return banner_info
        except Exception as e:
            self.logger.error(f"Error retrieving server banner: {e}")
            return banner_info

    def check_https_redirect(self):
        """Check if HTTP redirects to HTTPS."""
        self.logger.info(f"Checking if HTTP redirects to HTTPS on {self.target}...")

        try:
            url = f"http://{self.target}:80/"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')

            # Set up to follow redirects
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())

            try:
                response = opener.open(req, timeout=self.timeout)
                final_url = response.geturl()

                if final_url.startswith('https://'):
                    self.logger.info("HTTP redirects to HTTPS (Good!)")
                    return True
                else:
                    self.logger.warning("HTTP does NOT redirect to HTTPS")
                    return False
            except urllib.error.URLError:
                self.logger.info("HTTP port not accessible (might be expected)")
                return None
        except Exception as e:
            self.logger.error(f"Error checking HTTPS redirect: {e}")
            return None

    def get_ssl_protocols(self):
        """Check supported SSL/TLS protocols."""
        self.logger.info(f"Checking supported SSL/TLS protocols on {self.target}:{self.port}...")
        protocols = {}

        protocol_versions = [
            ('PROTOCOL_SSLv2', 'SSLv2'),
            ('PROTOCOL_SSLv3', 'SSLv3'),
            ('PROTOCOL_TLSv1', 'TLSv1.0'),
            ('PROTOCOL_TLSv1_1', 'TLSv1.1'),
            ('PROTOCOL_TLSv1_2', 'TLSv1.2'),
            ('PROTOCOL_TLS', 'TLS (Auto)'),
        ]

        for proto_attr, proto_name in protocol_versions:
            if hasattr(ssl, proto_attr):
                try:
                    context = ssl.SSLContext(getattr(ssl, proto_attr))
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                            protocols[proto_name] = 'SUPPORTED'
                            # Check if deprecated
                            if 'SSLv' in proto_name or 'TLSv1.0' in proto_name or 'TLSv1.1' in proto_name:
                                protocols[proto_name] = 'SUPPORTED (DEPRECATED - VULNERABLE!)'
                                self.logger.warning(f"{proto_name} is supported but deprecated!")
                except:
                    protocols[proto_name] = 'NOT SUPPORTED'

        return protocols

    def close(self):
        """Clean up resources."""
        self.logger.info("HTTPS enumeration completed.")

if __name__ == '__main__':
    # Test execution example
    enum = HTTPSEnumerator('google.com', port=443)
    if enum.connect():
        cert_info = enum.get_certificate_info()
        for k, v in cert_info.items():
            print(f"{k}: {v}")

        vulns = enum.check_certificate_vulnerabilities()
        print("\nVulnerabilities:")
        for k, v in vulns.items():
            print(f"{k}: {v}")

        banner = enum.get_server_banner()
        print("\nServer Banner:")
        for k, v in banner.items():
            print(f"{k}: {v}")

        enum.close()
