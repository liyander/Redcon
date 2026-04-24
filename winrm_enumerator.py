import logging
try:
    from pypsrp.client import Client
    from pypsrp.exceptions import AuthenticationError, WSManFaultError
except ImportError:
    Client = None

class WinRMEnumerator:
    def __init__(self, target, username='', password='', domain='', lmhash='', nthash='', port=5985, use_ssl=False):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.use_ssl = use_ssl
        self.nthash = nthash
        self.client = None
        
        # Configure logging
        self.logger = logging.getLogger('WinRMEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        if Client is None:
            self.logger.error("pypsrp module not found. Please install it using 'pip install pypsrp'")

    def connect(self):
        """Establish a WinRM connection to the target."""
        if Client is None:
            return False

        full_user = self.username
        if self.domain:
            full_user = f"{self.domain}\\{self.username}"

        self.logger.info(f"Establishing WinRM connection to {self.target}:{self.port} as {full_user}...")
        
        try:
            # Set up the Client, pypsrp can handle NTLM hashes if provided via the password field or specifically
            # depending on the transport. If passing a hash, it's typically formatted as LM:NT or just NT if supported.
            auth_password = self.password
            if self.nthash and not self.password:
                # pypsrp supports passing hashes in ntlm auth via string formatting
                auth_password = f"{self.nthash}"
                self.logger.info("Using NTLM Hash for authentication.")

            self.client = Client(
                self.target, 
                port=self.port,
                username=full_user, 
                password=auth_password,
                ssl=self.use_ssl,
                cert_validation=False
            )
            
            # Simple command to test connection
            output, streams, had_errors = self.client.execute_cmd('whoami')
            if had_errors:
                self.logger.warning("Connection authenticated, but 'whoami' returned an error.")
            
            self.logger.info("Successfully connected and authenticated via WinRM.")
            return True

        except AuthenticationError:
            self.logger.error("Authentication failed. Invalid credentials or hash.")
            return False
        except Exception as e:
            self.logger.error(f"WinRM Connection Error: {e}")
            return False

    def execute_command(self, cmd):
        """Execute a standard CMD command over WinRM."""
        if not self.client:
            self.logger.error("No active WinRM connection.")
            return None

        self.logger.info(f"Executing CMD Command: {cmd}")
        try:
            stdout, streams, had_errors = self.client.execute_cmd(cmd)
            return stdout.strip()
        except Exception as e:
            self.logger.error(f"Error executing command: {e}")
            return None

    def execute_powershell(self, script):
        """Execute a PowerShell script over WinRM."""
        if not self.client:
            self.logger.error("No active WinRM connection.")
            return None

        self.logger.info(f"Executing PS Command: {script}")
        try:
            stdout, streams, had_errors = self.client.execute_ps(script)
            return stdout.strip()
        except Exception as e:
            self.logger.error(f"Error executing PowerShell: {e}")
            return None

    def close(self):
        """Clean up WinRM resources."""
        # pypsrp Client handles its own session cleanup reasonably well, but we can drop the reference 
        self.client = None
        self.logger.info("WinRM session closed.")

if __name__ == '__main__':
    # Test execution example
    enum = WinRMEnumerator('127.0.0.1', domain='test.local', username='Administrator', password='Password123!')
    if enum.connect():
        print(enum.execute_command('hostname'))
        print(enum.execute_powershell('Get-ComputerInfo | Select-Object -ExpandProperty OsName'))
        enum.close()
