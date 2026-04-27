# Active Directory Enumeration Tool (Redcon)

A comprehensive modular enumeration and reconnaissance framework written in Python. This tool connects to target machines natively using standard libraries and `impacket` to gather intelligence across Active Directory domains, web services, APIs, and Linux systems without relying on heavy frameworks.

## Current Capabilities

### **SMB Enumeration Module**
- **Authentication Methods Supported:**
  - Anonymous Login (Null Sessions)
  - Credentialed Login (Username & Password)
  - Pass-the-Hash (NTLM Hashes)
- **Share Enumeration:**
  - Lists all visible SMB shares on the target.
  - Extracts the names and remarks of each share.
- **Domain Password Policy Extraction (via SAMR):**
  - Connects to the SAMR named pipe over SMB.
  - Enumerates the primary domain.
  - Extracts the Minimum Password Length.
  - Extracts the Password History Length.
  - Extracts the Account Lockout Threshold.

### **LDAP Enumeration Module**
- **Authentication Methods Supported:**
  - Anonymous LDAP Bind
  - Credentialed Bind (Username & Password)
  - Pass-the-Hash over LDAP
  - Support for both LDAP (port 389) and LDAPS / SSL (port 636)
- **Whoami Property Extraction:**
  - Extracts the fine-grained Active Directory object properties mimicking the NXC `whoami` module.
  - Queries `pwdLastSet`, `badPwdCount`, `userAccountControl`, `memberOf`, and `servicePrincipalName`.
- **User Enumeration:**
  - Queries `sAMAccountName`, `description`, and `userAccountControl`.
  - Dumps a list of all domain users and their descriptions.
- **Computer Enumeration:**
  - Queries `sAMAccountName` and `dNSHostName`.
  - Dumps a list of all domain computers and their fully qualified DNS names.

### **WinRM Execution Module**
- **Authentication Methods Supported:**
  - Credentialed Logins
  - Pass-the-Hash
- **Remote Execution:**
  - Establishes a remote connection over WS-Management.
  - Can execute standard CMD terminal commands.
  - Can execute raw PowerShell scripting natively.

### **FTP Enumeration Module**
- **Authentication Methods Supported:**
  - Anonymous Login (default)
  - Credentialed Logins
- **Capabilities:**
  - Standard directory listing (`ls`).
  - Download remote files (`get`).
  - Upload local files (`put`).

### **MSSQL Enumeration Module**
- **Authentication Methods Supported:**
  - Windows Authentication (NTLM & Pass-the-Hash)
  - SQL Server Authentication
- **Capabilities:**
  - List all MSSQL databases (`db-list`).
  - Execute arbitrary raw SQL queries (`query`).

### **ADCS Enumeration Module**
- **Capabilities:**
  - Enumerates Active Directory Certificate Services (Enterprise CAs).
  - Extracts published Certificate Templates and flags potentially vulnerable configurations (like ESC1).

### **Linux Privilege Escalation Enumerator (SSH)**
- **Authentication Methods Supported:**
  - Standard Password Login
  - Private Key Login (`--ssh-key`)
- **Capabilities:**
  - Context Enumeration (UID, Kernel, Hostname)
  - Sudo Privilege Checks (tests standard execution with password and reports binaries).
  - SUID Binaries (Maps out misconfigurations and flags GTFOBins)
  - Cron Tasks Systemd Timers (Dumps User Crontab, /etc/crontab)

### **Network Port Scanner**
- **Capabilities:**
  - Multi-threaded fast port scanning of common AD/Linux protocols.
  - Basic banner grabbing with automated HTTP/HTTPs Server header filtering to discover underlying services natively.

### **HTTPS/TLS Enumeration Module**
- **Capabilities:**
  - Extract detailed SSL/TLS certificate information (Subject, Issuer, Serial Number, Validity).
  - Identify Subject Alternative Names (SANs) for domain discovery.
  - Check for certificate vulnerabilities:
    - Self-signed certificates
    - Expired certificates
    - Wildcard certificates
    - Weak issuers
  - Retrieve server banner and HTTP headers (Server, X-Powered-By, etc.).
  - Enumerate supported SSL/TLS protocol versions (detect deprecated/vulnerable protocols).
  - Verify HTTP to HTTPS redirect configuration.

### **API Enumeration Module**
- **Authentication Methods Supported:**
  - Anonymous access
  - Basic Authentication (Username & Password)
- **Capabilities:**
  - Discover common API paths (`/api`, `/api/v1`, `/swagger`, `/openapi.json`, `/graphql`, etc.).
  - Enumerate common API endpoints (`/users`, `/admin`, `/auth`, `/products`, etc.).
  - Check for common API vulnerabilities:
    - Missing authentication on sensitive endpoints
    - CORS misconfiguration (Allow-Origin: *, overly permissive headers)
    - Exposed API documentation (Swagger, OpenAPI, API Docs)
    - Debug endpoints exposure (`/actuator`, `/health`, `/debug`)
  - Test for default API credentials (admin/admin, user/user, etc.).
  - Identify API version from endpoint responses.
  - Support for both HTTP and HTTPS protocols with custom ports.

## Prerequisites & Installation

The primary dependencies for this tool are the `impacket` and `pypsrp` libraries. Ensure you have Python installed and run the following to install them:

```bash
pip install impacket pypsrp
```

## Usage Instructions

The main entry point for the tool is `main.py`. You can view the help menu for available arguments:

```bash
python main.py -h
```

### Command Line Arguments

- `-t`, `--target`: (Required) Target IP or hostname.
- `-u`, `--username`: Username for authentication (Defaults to an anonymous login).
- `-p`, `--password`: Password for authentication.
- `-d`, `--domain`: Target domain.
- `--hashes`: NTLM hashes for authentication in the format `LMHASH:NTHASH` or just `NTHASH`.
- `--shares`: Flag to execute the Share Enumeration capability.
- `--policy`: Flag to execute Domain Password Policy Extraction via SAMR.
- `--smb-port`: Custom port for SMB (defaults to 445).
- `--users`: Flag to execute Domain User Enumeration via LDAP.
- `--whoami`: Execute the "Whoami" property extraction via LDAP for the authenticated user (or pass a username to query them).
- `--computers`: Flag to execute Domain Computer Enumeration via LDAP.
- `--asreproast`: Query LDAP for users configured with `DONT_REQUIRE_PREAUTH` (vulnerable to AS-REP roasting).
- `--adcs`: Enumerate Active Directory Certificate Services and Certificate Templates.
- `--ldap-port`: Custom port for LDAP (defaults to 389, auto-switches to 636 with `--ldaps`).
- `--ldaps`: Flag to use LDAPS (SSL over port 636) instead of standard LDAP.
- `--linux-enum`: Execute Linux Privilege Escalation Checks (Sudo, SUID, Cron) via a remote SSH Connection.
- `--ssh-port`: Configure a custom port for the Linux enumerator SSH connection (defaults to 22).
- `--ssh-key`: Path to an Ed25519 or RSA local private key file to log into the SSH session.
- `--scan-ports`: Trigger a multi-threaded banner-grabbing port scan against the target.
- `--all-ports`: Adjust the port scanner to sweep all 65,535 TCP ports utilizing an aggressive 500-thread pool.
- `--auto`: Automatically execute a generic footprinting scan and recursively trigger enumeration components based on open ports found on the target network.
- `-v`, `--verbose`: Print open ports live as they are discovered during scanning.
- `-x`, `--execute`: Execute a standard CMD command via WinRM functionality (e.g., `"whoami"`).
- `-X`, `--ps-execute`: Execute a PowerShell script/command over WinRM (e.g., `"Get-ComputerInfo"`).
- `--winrm-port`: Custom port for WinRM (defaults to 5985).
- `--ls`: List files in a remote FTP directory (defaults to current directory if no path given).
- `--get`: Download a file from the FTP server.
- `--put`: Upload a file to the FTP server (takes two arguments: `LOCAL_FILE REMOTE_FILE`).
- `--ftp-port`: Custom port for FTP (defaults to 21).
- `--mssql-port`: Custom port for MSSQL (defaults to 1433).
- `--sql-auth`: Force the connection to use standard SQL Server Authentication instead of Active Directory Windows Authentication.
- `--db-list`: List available databases on the MSSQL server.
- `-q`, `--query`: Execute a raw SQL query and print the tabular results.
- `--https`: Flag to execute HTTPS/TLS certificate enumeration.
- `--https-port`: Custom port for HTTPS (defaults to 443).
- `--cert-info`: Extract detailed SSL/TLS certificate information.
- `--cert-vulns`: Check for SSL/TLS certificate vulnerabilities.
- `--ssl-protocols`: Check supported SSL/TLS protocol versions (detect deprecated protocols).
- `--server-banner`: Grab server banner and HTTP headers from HTTPS endpoint.
- `--api`: Flag to execute API enumeration checks.
- `--api-port`: Custom port for API enumeration (defaults to 443).
- `--api-protocol`: Set API protocol to `http` or `https` (defaults to https).
- `--api-paths`: Discover common API paths (`/api`, `/swagger`, `/openapi.json`, etc.).
- `--api-endpoints`: Discover common API endpoints (`/users`, `/admin`, `/products`, etc.).
- `--api-vulns`: Check for common API vulnerabilities (missing auth, CORS, exposed docs).
- `--api-creds`: Test for default API credentials.
- `--api-all`: Execute all API enumeration checks at once.

## Examples

### 1. Anonymous Login / Null Session
Attempt to connect unauthenticated and see if you can pull standard shares:
```bash
python main.py -t 192.168.1.100 --shares
```

### 2. Standard Credential Login
Connect using a known Active Directory account to enumerate both shares and the domain password policy:
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u jsmith -p 'Password123!' --shares --policy
```

### 3. Pass-the-Hash (PtH)
Authenticate if you only possess an NTLM hash (useful if you've dumped hashes from another machine):
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u administrator --hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 --policy
```

### 4. LDAP Whoami Extraction
Connect to LDAP and extract the complete detailed dataset for the authenticated user matching the "whoami" module from larger frameworks:
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u jsmith -p 'Password123!' --whoami
```

### 5. LDAP User & Computer Enumeration
Query the domain controller for all users and computers using credentials:
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u jsmith -p 'Password123!' --users --computers
```

### 5. LDAPS (SSL) Connection
Connect securely over LDAPS to perform the LDAP enumeration (useful if the domain requires LDAP channel binding/signing):
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u administrator --hashes :31d6cfe0d16ae931b73c59d7e0c089c0 --users --ldaps
```

### 6. WinRM Command Execution
Get the hostname securely via a remote WinRM standard shell:
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u administrator -p 'Password123!' -x "hostname"
```

### 7. WinRM PowerShell Execution
Execute a PowerShell command over WinRM:
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u administrator -p 'Password123!' -X "Get-ComputerInfo | Select-Object -ExpandProperty OsName"
```

### 8. FTP Anonymous Enumeration
Attempt to login anonymously to the FTP server and list the root directory:
```bash
python main.py -t 192.168.1.100 --ls
```

### 9. FTP File Download
Download a specific file using credentials:
```bash
python main.py -t 192.168.1.100 -u ftpuser -p 'P@ssword!' --get "Confidential/backups.zip"
```

### 10. MSSQL Database Enumeration (Pass-the-Hash)
Enumerate the databases mapping over Windows Authentication utilizing an NTLM Hash:
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u administrator --hashes :31d6cfe0d16ae931b73c59d7e0c089c0 --db-list
```

### 11. MSSQL Custom Query (SQL Auth)
Login using native SQL Server Authentication (e.g. `sa` account) and extract version information:
```bash
python main.py -t 192.168.1.100 -u sa -p 'Password123!' --sql-auth -q "SELECT @@VERSION"
```

### 12. ADCS & Certipy Template Enumeration
Enumerate Enterprise Certificate Authorities and published certificate templates to identify vectors out of the box like ESC1 and ESC8:
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u jsmith -p 'Password123!' --adcs
```

### 13. AS-REP Roastable Account Discovery
Scan LDAP for configuration flaws where user accounts have been explicitly set to not require Kerberos Pre-Authentication:
```bash
python main.py -t 192.168.1.100 -d inlanefreight.local -u jsmith -p 'Password123!' --asreproast
```

### 14. Linux Enumeration (SSH)
Authenticate effectively to a bound Linux target using typical credentials and dump standard Linux exploitation vectors (Cron, SUID, Sudo):
```bash
python main.py -t 192.168.1.50 -u root -p 'toor' --linux-enum
```

### 15. Service & Port Discovery
Kick off a multi-threaded network scan against standard Active Directory and internal assessment ports, extracting service banners independently without authentication:
```bash
python main.py -t 192.168.1.100 --scan-ports
```
To sweep the entire 1-65535 TCP port range aggressively:
```bash
python main.py -t 192.168.1.100 --all-ports
```

### 16. HTTPS/TLS Certificate Enumeration
Extract certificate information and check for vulnerabilities:
```bash
python main.py -t 192.168.1.100 --cert-info --cert-vulns
```
Or run all HTTPS checks at once:
```bash
python main.py -t 192.168.1.100 --https
```

### 17. HTTPS Server Banner Grabbing
Grab server banner and HTTP headers from HTTPS endpoint:
```bash
python main.py -t 192.168.1.100 --server-banner
```

### 18. Check Supported SSL/TLS Protocols
Identify supported protocol versions and detect deprecated/vulnerable ones:
```bash
python main.py -t 192.168.1.100 --ssl-protocols
```

### 19. API Path and Endpoint Discovery
Discover common API paths and endpoints:
```bash
python main.py -t 192.168.1.100 --api-paths --api-endpoints
```

### 20. API Vulnerability Scanning
Check for common API vulnerabilities (missing auth, CORS, exposed documentation):
```bash
python main.py -t 192.168.1.100 --api-vulns
```

### 21. Test API Default Credentials
Test for default credentials on API endpoints:
```bash
python main.py -t 192.168.1.100 --api-creds
```

### 22. Comprehensive API Enumeration
Run all API enumeration checks with custom port and authentication:
```bash
python main.py -t 192.168.1.100 --api-port 8080 --api-protocol http -u admin -p 'Password123!' --api-all
```

### 23. Auto-Enumeration Pilot
Provide one set of standard credentials and automatically sweep the host, executing related modules universally across the network topology dynamically depending on what services are actually online:
```bash
python main.py -t 192.168.10.15 -u 'svc_account' -p 'Sect0r3X' --auto -v
```

## Future Expansion
This modular architecture is designed to expand. Future iterations will include modules for core AD vectors such as Kerberos querying (e.g., Kerberoasting), advanced RPC-based enumeration, WebDAV exploitation, DNS enumeration, and additional cloud platform assessments.
