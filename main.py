# -*- coding: utf-8 -*-
import argparse
import os
from smb_enumerator import SMBEnumerator
from ldap_enumerator import LDAPEnumerator
from winrm_enumerator import WinRMEnumerator
from ftp_enumerator import FTPEnumerator
from mssql_enumerator import MSSQLEnumerator
from adcs_enumerator import ADCSEnumerator
from ssh_enumerator import SSHEnumerator
from port_scanner import PortScanner

# Enable ANSI colors on Windows
os.system("") 
RED = "\033[91m"
BLUE = "\033[94m"
GREEN = "\033[92m"
GREY = "\033[90m"
RESET = "\033[0m"

BANNER = f"""
{RED}
    ██████╗ ███████╗██████╗  ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██║  ██║██║     ██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║  ██║██║     ██║   ██║██║╚██╗██║
    ██║  ██║███████╗██████╔╝╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}{GREY}
    ──────────────────────────────────────────────────────
     Modular Recon & Enumeration Framework    v1.0
     Protocols: SMB | LDAP | WinRM | FTP | MSSQL | SSH
     Modules  : ADCS | AS-REP Roast | Port Scanner
    ──────────────────────────────────────────────────────
{RESET}"""

def print_banner():
    print(BANNER)

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Redcon - Modular Recon & Enumeration Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-t', '--target', required=True, help="Target IP or hostname")
    parser.add_argument('-u', '--username', default='', help="Username for authentication (default: anonymous)")
    parser.add_argument('-p', '--password', default='', help="Password for authentication")
    parser.add_argument('-d', '--domain', default='', help="Domain for authentication")
    parser.add_argument('--hashes', default='', help="NTLM hashes, format is LMHASH:NTHASH")
    parser.add_argument('--shares', action='store_true', help="Enumerate SMB shares")
    parser.add_argument('--policy', action='store_true', help="Enumerate Domain Password Policy via SAMR")
    parser.add_argument('--smb-port', type=int, default=445, help="SMB Port (default: 445)")
    parser.add_argument('--users', action='store_true', help="Enumerate Domain Users via LDAP")
    parser.add_argument('--computers', action='store_true', help="Enumerate Domain Computers via LDAP")
    parser.add_argument('--whoami', nargs='?', const=True, metavar='USER', help="Extract detailed property info for the logged in user or a specified user via LDAP")
    parser.add_argument('--asreproast', action='store_true', help="Enumerate users vulnerable to AS-REP Roasting (DONT_REQUIRE_PREAUTH)")
    parser.add_argument('--ldap-port', type=int, default=389, help="LDAP Port (default: 389, auto-switches to 636 with --ldaps)")
    parser.add_argument('--ldaps', action='store_true', help="Use LDAPS (SSL) for LDAP enumeration")
    parser.add_argument('-x', '--execute', type=str, help="Execute a standard CMD command via WinRM")
    parser.add_argument('-X', '--ps-execute', type=str, help="Execute a PowerShell script/command via WinRM")
    parser.add_argument('--winrm-port', type=int, default=5985, help="WinRM Port (default: 5985)")
    
    # FTP Arguments
    parser.add_argument('--ftp-port', type=int, default=21, help="FTP Port (default: 21)")
    parser.add_argument('--ls', nargs='?', const='.', metavar='DIRECTORY', help="List files in FTP directory")
    parser.add_argument('--get', metavar='FILE', help="Download a file via FTP")
    parser.add_argument('--put', nargs=2, metavar=('LOCAL_FILE', 'REMOTE_FILE'), help="Upload a file via FTP")
    
    # MSSQL Arguments
    parser.add_argument('--mssql-port', type=int, default=1433, help="MSSQL Port (default: 1433)")
    parser.add_argument('--sql-auth', action='store_true', help="Use SQL Server Authentication instead of Windows Auth")
    parser.add_argument('--db-list', action='store_true', help="List all MSSQL databases")
    parser.add_argument('-q', '--query', type=str, help="Execute a raw SQL query against the database")

    # ADCS Arguments
    parser.add_argument('--adcs', action='store_true', help="Enumerate Active Directory Certificate Services (ADCS) & Templates via LDAP")

    # SSH / Linux Arguments
    parser.add_argument('--ssh-port', type=int, default=22, help="SSH Port (default: 22)")
    parser.add_argument('--ssh-key', type=str, help="Path to an SSH Private Key file for authentication")
    parser.add_argument('--linux-enum', action='store_true', help="Perform Linux PE enumeration (Sudo, SUID, Cron, Context) over SSH")

    # Port Scanner Arguments
    parser.add_argument('--scan-ports', action='store_true', help="Scan the target for common open ports and grab their service banners")
    parser.add_argument('--all-ports', action='store_true', help="Scan all 65535 TCP ports instead of just common ones (combines with --scan-ports)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Print progress and findings dynamically (e.g. print ports live as they are found)")
    parser.add_argument('--auto', action='store_true', help="Automatically run Port Scanner and trigger subsequent enumeration actions based on open ports found.")

    args = parser.parse_args()

    lmhash = ''
    nthash = ''
    if args.hashes:
        if ':' in args.hashes:
            lmhash, nthash = args.hashes.split(':')
        else:
            nthash = args.hashes

    print(f"[*] Starting Enumeration on {args.target}")
    
    if args.auto:
        args.all_ports = True

    # 0. PORT SCANNING (Moved to Top for Orchestration)
    open_ports = []
    scan_results = []
    if args.scan_ports or args.all_ports:
        port_list = range(1, 65536) if args.all_ports else None
        scanner = PortScanner(target=args.target, ports=port_list)
        
        max_threads = 500 if args.all_ports else 50
        timeout = 0.5 if args.all_ports else 1.0
        
        scan_results = scanner.scan_all(max_workers=max_threads, connect_timeout=timeout, verbose=args.verbose)
        if scan_results:
            print(f"\n{BLUE}============ [ TCP SERVICE SCAN ] ============{RESET}")
            for r in scan_results:
                open_ports.append(r['port'])
                if not args.verbose:
                    print(f" {BLUE}[+]{RESET} Port: {str(r['port']).ljust(5)}  |  Service Banner: {r['banner']}")
            print(f"{BLUE}=============================================={RESET}\n")
        else:
            print(f"{RED}[-] No open ports found on the target.{RESET}")

    has_creds = bool(args.username and (args.password or args.hashes))

    if args.auto:
        print("[*] Auto mode enabled. Mapping enumeration tasks to discovered ports...")
        if not has_creds:
            print(" [Auto] No credentials provided. Only unauthenticated checks will run.")
            print(" [Auto] Provide -u and -p to unlock full authenticated enumeration.\n")

        # Build service map from both port numbers AND banner fingerprints
        detected_services = set()
        ssh_ports_found = []
        for r in scan_results:
            port = r['port']
            banner = r.get('banner', '').lower()

            # SMB detection
            if port == 445 or port == 139:
                detected_services.add('smb')
            # LDAP detection
            if port in [389, 636] or 'ldap' in banner:
                detected_services.add('ldap')
                if port == 636: args.ldaps = True
            # MSSQL detection
            if port == 1433 or 'mssql' in banner or 'sql server' in banner:
                detected_services.add('mssql')
                args.mssql_port = port
            # FTP detection
            if port == 21 or 'ftp' in banner or 'vsftpd' in banner or 'proftpd' in banner:
                detected_services.add('ftp')
                args.ftp_port = port
            # SSH detection (collect ALL SSH ports)
            if 'ssh' in banner or port == 22:
                detected_services.add('ssh')
                ssh_ports_found.append(port)
            # WinRM detection
            if port in [5985, 5986] or 'wsman' in banner:
                detected_services.add('winrm')
            # HTTP detection
            if port in [80, 443, 8080, 8443, 8000, 5173, 4000] or 'http' in banner or 'server:' in banner or 'werkzeug' in banner or 'nginx' in banner or 'apache' in banner:
                detected_services.add('http')

        # Map detected services to enumeration modules
        if 'smb' in detected_services:
            print(f" {BLUE}[Auto] SMB Detected -> Selecting Share & Policy Enumeration{RESET}")
            args.shares = True
            args.policy = True
        if 'ldap' in detected_services:
            print(f" {BLUE}[Auto] LDAP Detected -> Selecting Users, Computers, AS-REP Roast, ADCS{RESET}")
            args.users = True
            args.computers = True
            args.asreproast = True
            args.adcs = True
        if 'mssql' in detected_services:
            print(f" {BLUE}[Auto] MSSQL Detected (port {args.mssql_port}) -> Selecting DB Enumeration{RESET}")
            args.db_list = True
        if 'ftp' in detected_services:
            print(f" {BLUE}[Auto] FTP Detected (port {args.ftp_port}) -> Selecting Directory Listing{RESET}")
            args.ls = "/" if not args.ls else args.ls
        if 'ssh' in detected_services:
            print(f" {BLUE}[Auto] SSH Detected on ports: {ssh_ports_found} -> Selecting Linux Enumerator{RESET}")
            args.linux_enum = True
            args._ssh_ports_list = ssh_ports_found
        if 'winrm' in detected_services and has_creds:
            print(f" {BLUE}[Auto] WinRM Detected -> Selecting WinRM whoami check{RESET}")
            args.execute = "whoami /all"
        if 'http' in detected_services:
            http_ports = [r['port'] for r in scan_results if r['port'] in [80, 443, 8080, 8443, 8000, 5173, 4000] or any(kw in r.get('banner','').lower() for kw in ['http', 'server:', 'werkzeug', 'nginx', 'apache'])]
            print(f" {BLUE}[Auto] HTTP Services Detected on ports: {http_ports}{RESET}")
        print("")
            
    # 1. SMB ENUMERATION
    if args.shares or args.policy:
        try:
            smb_enum = SMBEnumerator(
                target=args.target, 
                username=args.username, 
                password=args.password, 
                domain=args.domain, 
                lmhash=lmhash, 
                nthash=nthash,
                port=args.smb_port
            )
            if smb_enum.connect():
                if args.shares:
                    print(f"\n{BLUE}[*] Performing Share Enumeration:{RESET}")
                    shares = smb_enum.enumerate_shares()
                    for share in shares:
                        print(f"    - {BLUE}{share['name']}{RESET} (Remark: {share['remark']})")

                if args.policy:
                    print(f"\n{BLUE}[*] Performing Password Policy Enumeration:{RESET}")
                    policies = smb_enum.get_password_policy()
                    if policies:
                        for domain_name, policy in policies.items():
                            print(f"    Domain: {BLUE}{domain_name}{RESET}")
                            for k, v in policy.items():
                                print(f"        {k}: {RED}{v}{RESET}")
                
                smb_enum.close()
            else:
                print(f"{RED}[-]{RESET} Failed to connect to target via SMB.")
        except Exception as e:
            print(f"{RED}[-] SMB Enumeration Error: {e}{RESET}")

    # 2. LDAP ENUMERATION
    if args.users or args.computers or args.whoami or args.asreproast:
        try:
            ldap_enum = LDAPEnumerator(
                target=args.target, 
                username=args.username, 
                password=args.password, 
                domain=args.domain, 
                lmhash=lmhash, 
                nthash=nthash,
                port=args.ldap_port,
                use_ssl=args.ldaps
            )
            if ldap_enum.connect():
                if args.whoami:
                    target_user = args.whoami if isinstance(args.whoami, str) else None
                    print(f"\n{BLUE}[*] Performing LDAP 'whoami' properties extraction:{RESET}")
                    info = ldap_enum.get_whoami_info(target_user)
                    if info:
                        for k, v in info.items():
                            print(f"    - {BLUE}{k}{RESET}: {v}")
                    else:
                        print(f"    {RED}[-] Could not extract properties.{RESET}")

                if args.users:
                    print(f"\n{BLUE}[*] Performing LDAP User Enumeration:{RESET}")
                    users = ldap_enum.enumerate_users()
                    for user in users:
                        print(f"    - {BLUE}{user['username']}{RESET} | Desc: {user['description']}")
                
                if args.computers:
                    print(f"\n{BLUE}[*] Performing LDAP Computer Enumeration:{RESET}")
                    computers = ldap_enum.enumerate_computers()
                    for comp in computers:
                        print(f"    - {BLUE}{comp['name']}{RESET} | DNS: {comp['dns_name']}")
                
                if args.asreproast:
                    print(f"\n{RED}[*] Performing AS-REP Roasting User Enumeration:{RESET}")
                    vuln_users = ldap_enum.enumerate_asrep_roastable()
                    for u in vuln_users:
                        print(f"    - User: {RED}{u['username']}{RESET} (UPN: {u['upn']})")

                ldap_enum.close()
            else:
                print(f"{RED}[-] Failed to connect to target via LDAP.{RESET}")
        except Exception as e:
            print(f"{RED}[-] LDAP Enumeration Error: {e}{RESET}")

    # 3. WINRM ENUMERATION
    if args.execute or args.ps_execute:
        try:
            winrm_enum = WinRMEnumerator(
                target=args.target, 
                username=args.username, 
                password=args.password, 
                domain=args.domain, 
                lmhash=lmhash, 
                nthash=nthash,
                port=args.winrm_port
            )
            if winrm_enum.connect():
                if args.execute:
                    print(f"{BLUE}[*] Executing CMD via WinRM: {args.execute}{RESET}")
                    res = winrm_enum.execute_command(args.execute)
                    print(f"Output:\n{RED}{res}{RESET}\n")
                
                if args.ps_execute:
                    print(f"{BLUE}[*] Executing PowerShell via WinRM: {args.ps_execute}{RESET}")
                    res = winrm_enum.execute_powershell(args.ps_execute)
                    print(f"Output:\n{RED}{res}{RESET}\n")
                
                winrm_enum.close()
            else:
                print(f"{RED}[-] Failed to connect to target via WinRM.{RESET}")
        except Exception as e:
            print(f"{RED}[-] WinRM Enumeration Error: {e}{RESET}")

    # 4. FTP ENUMERATION
    if args.ls or args.get or args.put:
        try:
            ftp_enum = FTPEnumerator(
                target=args.target,
                username=args.username,
                password=args.password,
                port=args.ftp_port
            )
            if ftp_enum.connect():
                if args.ls:
                    print(f"\n{BLUE}[*] Listing FTP Directory: {args.ls}{RESET}")
                    files = ftp_enum.list_files(args.ls)
                    for f in files:
                        print(f"    {BLUE}- {f}{RESET}")
                
                if args.get:
                    print(f"\n{BLUE}[*] Downloading file via FTP: {args.get}{RESET}")
                    if ftp_enum.download_file(args.get):
                        print(f"{RED}[+] Download complete.{RESET}")
                    else:
                        print(f"{RED}[-] Download failed.{RESET}")
                
                if args.put:
                    local_file, remote_file = args.put
                    print(f"\n{BLUE}[*] Uploading {local_file} -> {remote_file} via FTP...{RESET}")
                    if ftp_enum.upload_file(local_file, remote_file):
                        print(f"{RED}[+] Upload complete.{RESET}")
                    else:
                        print(f"{RED}[-] Upload failed.{RESET}")
                
                ftp_enum.close()
            else:
                print(f"{RED}[-] Failed to connect to target via FTP.{RESET}")
        except Exception as e:
            print(f"{RED}[-] FTP Enumeration Error: {e}{RESET}")

    # 5. MSSQL ENUMERATION
    if args.db_list or args.query:
        try:
            mssql_enum = MSSQLEnumerator(
                target=args.target,
                username=args.username,
                password=args.password,
                domain=args.domain,
                lmhash=lmhash,
                nthash=nthash,
                port=args.mssql_port,
                windows_auth=not args.sql_auth
            )
            
            if mssql_enum.connect():
                if args.db_list:
                    print(f"\n{BLUE}[*] Enumerating MSSQL Databases:{RESET}")
                    mssql_enum.list_databases()
                    
                if args.query:
                    print(f"\n{BLUE}[*] Executing SQL Query: {args.query}{RESET}")
                    print(f"{RED}------------- RESULT -------------{RESET}")
                    mssql_enum.execute_query(args.query)
                    print(f"{RED}----------------------------------{RESET}")
                    
                mssql_enum.close()
            else:
                print(f"{RED}[-] Failed to connect to target via MSSQL.{RESET}")
        except Exception as e:
            print(f"{RED}[-] MSSQL Enumeration Error: {e}{RESET}")

    # 6. ADCS ENUMERATION
    if args.adcs:
        try:
            adcs_enum = ADCSEnumerator(
                target=args.target, 
                username=args.username, 
                password=args.password, 
                domain=args.domain, 
                lmhash=lmhash, 
                nthash=nthash,
                use_ssl=args.ldaps
            )
            if adcs_enum.connect():
                print(f"\n{RED}[*] Enumerating Active Directory Certificate Services (ADCS):{RESET}")
                adcs_enum.enumerate_cas()
                adcs_enum.enumerate_templates()
                adcs_enum.close()
            else:
                print(f"{RED}[-] Failed to connect to target via LDAP for ADCS.{RESET}")
        except Exception as e:
            print(f"{RED}[-] ADCS Enumeration Error: {e}{RESET}")

    # 7. LINUX / SSH ENUMERATION
    if args.linux_enum:
        # Get list of all SSH ports to enumerate (auto mode collects multiple)
        ssh_ports_to_scan = getattr(args, '_ssh_ports_list', [args.ssh_port])
        
        for ssh_port in ssh_ports_to_scan:
            try:
                print(f"\n{BLUE}[*] Starting Linux Enumeration on SSH port {ssh_port}{RESET}")
                ssh_enum = SSHEnumerator(
                    target=args.target,
                    username=args.username,
                    password=args.password,
                    port=ssh_port,
                    key_file=args.ssh_key
                )
                if ssh_enum.connect():
                    ssh_enum.run_linux_enum()
                    ssh_enum.close()
                else:
                    print(f"{RED}[-] Failed to connect to target via SSH on port {ssh_port}.{RESET}")
            except Exception as e:
                print(f"{RED}[-] SSH Enumeration Error on port {ssh_port}: {e}{RESET}")

    print(f"\n{BLUE}[*] Enumeration Complete.{RESET}")

if __name__ == '__main__':
    main()
