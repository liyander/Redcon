import logging
import ftplib
import os

class FTPEnumerator:
    def __init__(self, target, username='', password='', port=21):
        self.target = target
        self.username = username if username else 'anonymous'
        self.password = password if password else 'anonymous@example.com'
        self.port = port
        self.ftp = None
        
        # Configure logging
        self.logger = logging.getLogger('FTPEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def connect(self):
        """Establish an FTP connection."""
        self.logger.info(f"Connecting to FTP on {self.target}:{self.port}...")
        try:
            self.ftp = ftplib.FTP()
            self.ftp.connect(self.target, self.port, timeout=10)
            
            self.logger.info(f"Authenticating as {self.username}...")
            self.ftp.login(self.username, self.password)
            
            self.logger.info("Successfully connected and authenticated via FTP.")
            return True
        except ftplib.error_perm as e:
            self.logger.error(f"FTP Authentication Failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"FTP Connection Error: {e}")
            return False

    def list_files(self, directory="."):
        """List files in the specified directory."""
        if not self.ftp:
            self.logger.error("No active FTP connection.")
            return []

        self.logger.info(f"Listing contents of {directory}...")
        files = []
        try:
            # Change directory if specified
            if directory and directory != ".":
                self.ftp.cwd(directory)
            
            # Using retrlines to get detailed list (like 'ls -la')
            self.ftp.retrlines('LIST', files.append)
            
            # Reset back to root if we changed it, just to be clean
            if directory and directory != ".":
                self.ftp.cwd("/")

            return files
        except Exception as e:
            self.logger.error(f"Error listing files: {e}")
            return files

    def download_file(self, remote_file, local_file=None):
        """Download a file from the remote FTP server."""
        if not self.ftp:
            self.logger.error("No active FTP connection.")
            return False

        if not local_file:
            local_file = os.path.basename(remote_file)

        self.logger.info(f"Downloading {remote_file} to {local_file}...")
        try:
            with open(local_file, "wb") as f:
                self.ftp.retrbinary(f"RETR {remote_file}", f.write)
            self.logger.info(f"Successfully downloaded {remote_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error downloading file: {e}")
            return False

    def upload_file(self, local_file, remote_file=None):
        """Upload a file to the remote FTP server."""
        if not self.ftp:
            self.logger.error("No active FTP connection.")
            return False

        if not remote_file:
            remote_file = os.path.basename(local_file)

        self.logger.info(f"Uploading {local_file} to {remote_file}...")
        try:
            with open(local_file, "rb") as f:
                self.ftp.storbinary(f"STOR {remote_file}", f)
            self.logger.info(f"Successfully uploaded {local_file}")
            return True
        except FileNotFoundError:
            self.logger.error(f"Local file {local_file} not found.")
            return False
        except Exception as e:
            self.logger.error(f"Error uploading file: {e}")
            return False

    def close(self):
        """Close the FTP connection."""
        if self.ftp:
            try:
                self.ftp.quit()
            except:
                self.ftp.close()
            self.ftp = None
            self.logger.info("FTP connection closed.")

if __name__ == '__main__':
    # Test execution example
    enum = FTPEnumerator('127.0.0.1', username='anonymous', password='')
    if enum.connect():
        files = enum.list_files()
        for f in files:
            print(f)
        enum.close()
