import logging
import paramiko
# test
class SSHEnumerator:
    def __init__(self, target, username='', password='', port=22, key_file=None):
        self.target = target
        self.username = username
        self.password = password
        self.port = port
        self.key_file = key_file
        self.ssh_client = None
        
        self.logger = logging.getLogger('SSHEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def connect(self):
        self.logger.info(f"Connecting to SSH on {self.target}:{self.port} as {self.username}...")
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                "hostname": self.target,
                "port": self.port,
                "username": self.username,
                "timeout": 10
            }
            
            if self.key_file:
                connect_kwargs["key_filename"] = self.key_file
            elif self.password:
                connect_kwargs["password"] = self.password
            else:
                self.logger.error("No password or key file provided for SSH.")
                return False
                
            self.ssh_client.connect(**connect_kwargs)
            self.logger.info("Successfully authenticated via SSH.")
            return True
        except Exception as e:
            self.logger.error(f"SSH Connection Error: {e}")
            return False

    def execute_command(self, command, redir_err=True):
        if not self.ssh_client:
            return ""
        try:
            cmd = f"{command} 2>&1" if redir_err else command
            stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
            return stdout.read().decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""

    def run_linux_enum(self):
        """Perform Linux Privilege Escalation Enumeration (Sudo, SUID, Cron, Context)."""
        if not self.ssh_client:
            self.logger.error("No active SSH connection.")
            return

        print("\n\n======== [ CONTEXT INFO ] ========")
        context_whoami = self.execute_command("whoami")
        context_id = self.execute_command("id")
        context_uname = self.execute_command("uname -a")
        
        print(f"[*] Current User: {context_whoami}")
        print(f"[*] UID/Groups: {context_id}")
        print(f"[*] Kernel: {context_uname}")
        
        print("\n======== [ SUDO INFO ] ========")
        print("[*] Checking sudo -l...")
        sudo_np = self.execute_command("sudo -n -l")
        password_required = False
        
        if sudo_np and ("a password is required" in sudo_np or "incorrect password attempt" in sudo_np):
            password_required = True
            
        sudo_out = sudo_np
        if password_required and self.password:
            safe_pass = self.password.replace("'", "'\\''")
            sudo_out = self.execute_command(f"echo '{safe_pass}' | sudo -S -l")

        if sudo_out:
            lines = sudo_out.split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith("[sudo]"): continue
                if "NOPASSWD" in line:
                    print(f"[!] NOPASSWD: {line}")
                elif "may run the following commands" in line:
                    print(f"[*] {line}")
                elif "(" in line and ")" in line:
                    print(f"[*] Rule: {line}")

        print("\n======== [ SUID BINARIES ] ========")
        print("[*] Finding SUID binaries. Highlighting GTFOBin candidates...")
        gtfobins = [
            "aria2c", "arp", "ash", "awk", "base64", "bash", "busybox", "cat", "chmod", "chown", "chroot", "cp", "csh", "curl",
            "cut", "dash", "date", "dd", "diff", "dmsetup", "docker", "emacs", "env", "eqn", "expand", "expect", "file", "find",
            "flock", "fmt", "fold", "gdb", "gimp", "git", "grep", "gtester", "hd", "head", "hexdump", "highlight", "iconv",
            "ionice", "ip", "jjs", "jq", "jrunscript", "ksh", "ksshell", "ld.so", "less", "logsave", "look", "lwp-download",
            "lwp-request", "make", "man", "mawk", "more", "mosquitto", "msgfilter", "mv", "nawk", "nc", "nice", "nl", "node",
            "nohup", "nmap", "od", "openssl", "perl", "pg", "php", "pic", "pico", "python", "readelf", "restic", "rlwrap", "rpm",
            "rpmquery", "rsync", "ruby", "run-parts", "rvim", "scp", "sed", "setarch", "shuf", "soelim", "sort", "start-stop-daemon",
            "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tclsh", "tee", "tftp", "time", "timeout",
            "ul", "unexpand", "uniq", "unshare", "uudecode", "uuencode", "vim", "watch", "wget", "xargs", "xxd", "xz", "zsh", "zsoelim"
        ]
        
        suid_out = self.execute_command("find / -perm -4000 -type f 2>/dev/null", redir_err=False)
        if suid_out:
            for path in suid_out.split('\n'):
                path = path.strip()
                if not path or "Permission denied" in path or "find:" in path: continue
                binary = path.split('/')[-1]
                
                if binary in gtfobins:
                    print(f"[!] GTFOBin: {path}")
                elif not (path.startswith("/bin/") or path.startswith("/sbin/") or path.startswith("/usr/bin/") or path.startswith("/usr/sbin/") or path.startswith("/usr/local/") or path.startswith("/usr/lib/") or path.startswith("/snap/")):
                    print(f"[*] Non-Standard SUID: {path}")

        print("\n======== [ CRON JOBS ] ========")
        print("[*] Retrieving Crontab info...")
        user_cron = self.execute_command("crontab -l 2>/dev/null")
        if user_cron and "no crontab for" not in user_cron:
            print(f"[*] User Crontab:\n{user_cron}")
            
        sys_cron = self.execute_command("cat /etc/crontab 2>/dev/null")
        if sys_cron and len(sys_cron) > 0:
            print(f"[*] /etc/crontab:\n{sys_cron}")

        systemd_timers = self.execute_command("systemctl list-timers --all --no-pager 2>/dev/null")
        if systemd_timers and "0 timers listed" not in systemd_timers:
            print(f"[*] Systemd Timers:\n{systemd_timers}")

    def close(self):
        if self.ssh_client:
            self.ssh_client.close()
            self.logger.info("SSH connection closed.")
