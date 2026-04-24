import logging
from impacket import tds

class MSSQLEnumerator:
    def __init__(self, target, username='', password='', domain='', lmhash='', nthash='', port=1433, db='', windows_auth=True):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.port = port
        self.db = db if db else None
        self.windows_auth = windows_auth
        self.ms_sql = None
        
        # Configure logging
        self.logger = logging.getLogger('MSSQLEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def connect(self):
        """Establish connection to MSSQL Database."""
        self.logger.info(f"Connecting to MSSQL on {self.target}:{self.port}...")
        try:
            self.ms_sql = tds.MSSQL(self.target, int(self.port))
            self.ms_sql.connect()
            
            # Pack hashes back together for impacket's login function if they exist
            hashes = None
            if self.nthash:
                hashes = f"{self.lmhash}:{self.nthash}" if self.lmhash else f":{self.nthash}"

            self.logger.info(f"Authenticating as {self.domain}\\{self.username} (Windows Auth: {self.windows_auth})...")
            res = self.ms_sql.login(self.db, self.username, self.password, self.domain, hashes, self.windows_auth)
            
            if res is not True:
                self.logger.error("MSSQL Authentication Failed.")
                return False
            
            self.logger.info("Successfully connected and authenticated via MSSQL.")
            return True
        except Exception as e:
            self.logger.error(f"MSSQL Connection/Authentication Error: {e}")
            return False

    def list_databases(self):
        """List all databases available on the server."""
        if not self.ms_sql:
            self.logger.error("No active MSSQL connection.")
            return []

        self.logger.info("Listing databases...")
        databases = []
        try:
            # Query standard system databases view
            self.ms_sql.sql_query("SELECT name FROM master..sysdatabases")
            # The result is stored in self.ms_sql.colMeta and self.ms_sql.rows
            # Or we can printRows directly. Let's extract properly:
            for row in self.ms_sql.rows:
                # row[0] is typically a dict or direct value depending on impacket version
                db_name = row[0]['Data'].decode('utf-16le').strip() if isinstance(row[0], dict) else str(row[0]['Data'])
                databases.append(db_name)
                self.logger.info(f"Found Database: {db_name}")
            return databases
        except Exception as e:
            self.logger.error(f"Error enumerating databases: {e}")
            # Try plain print iteration as fallback for raw display
            try:
                self.ms_sql.printRows()
            except:
                pass
            return databases

    def execute_query(self, query):
        """Execute an arbitrary SQL query."""
        if not self.ms_sql:
            self.logger.error("No active MSSQL connection.")
            return False

        self.logger.info(f"Executing Query: {query}")
        try:
            self.ms_sql.sql_query(query)
            self.ms_sql.printRows()
            return True
        except Exception as e:
            self.logger.error(f"Error executing query: {e}")
            return False

    def close(self):
        """Close the MSSQL connection."""
        if self.ms_sql:
            self.ms_sql.disconnect()
            self.logger.info("MSSQL connection closed.")

if __name__ == '__main__':
    # Test execution example
    enum = MSSQLEnumerator('127.0.0.1', username='sa', password='Password123!', windows_auth=False)
    if enum.connect():
        enum.list_databases()
        enum.close()
