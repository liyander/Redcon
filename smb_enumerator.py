import logging
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr
# test
class SMBEnumerator:
    def __init__(self, target, username='', password='', domain='', lmhash='', nthash='', port=445):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.port = port
        self.smb_conn = None
        
        # Configure a basic logger
        self.logger = logging.getLogger('SMBEnumerator')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def connect(self):
        """Establish SMB Connection."""
        self.logger.info(f"Connecting to {self.target}:{self.port} over SMB...")
        try:
            self.smb_conn = SMBConnection(self.target, self.target, sess_port=self.port)
            if self.username == '' and self.password == '':
                self.logger.info("Attempting anonymous login (null session)...")
                self.smb_conn.login('', '')
            else:
                self.logger.info(f"Authenticating as {self.domain}\\{self.username}...")
                self.smb_conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self.logger.info("Successfully connected and authenticated.")
            return True
        except SessionError as e:
            self.logger.error(f"Session Error during login: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Connection Error: {e}")
            return False

    def enumerate_shares(self):
        """Enumerate SMB shares available on the target."""
        if not self.smb_conn:
            self.logger.error("No active SMB connection.")
            return []

        self.logger.info("Enumerating shares...")
        shares = []
        try:
            resp = self.smb_conn.listShares()
            for share in resp:
                share_name = share['shi1_netname'][:-1]
                share_remark = share['shi1_remark'][:-1]
                shares.append({'name': share_name, 'remark': share_remark})
                self.logger.info(f"Found Share: {share_name} - {share_remark}")
            return shares
        except Exception as e:
            self.logger.error(f"Error enumerating shares: {e}")
            return shares

    def get_password_policy(self):
        """Connect to SAMR via SMB transport and dump password policy."""
        self.logger.info("Attempting to enumerate password policy via SAMR...")
        try:
            rpctransport = transport.SMBTransport(
                self.target,
                self.port,
                r'\samr',
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
            )
            dce = DCERPC_v5(rpctransport)
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Connect to SAMR
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']

            # Enumerate Domains
            resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle=server_handle)
            domains = resp2['Buffer']['Buffer']
            
            policy_data = {}
            for domain in domains:
                domain_name = domain['Name']
                self.logger.info(f"Found Domain: {domain_name}")
                
                resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle=server_handle, name=domain_name)
                resp4 = samr.hSamrOpenDomain(dce, serverHandle=server_handle, desiredAccess=samr.MAXIMUM_ALLOWED, domainId=resp3['DomainId'])
                domain_handle = resp4['DomainHandle']
                
                # Query Password Info
                resp_info = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
                min_pass_len = resp_info['Buffer']['Password']['MinPasswordLength']
                pass_history = resp_info['Buffer']['Password']['PasswordHistoryLength']
                
                # Query Lockout Info
                resp_lockout = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
                lockout_thresh = resp_lockout['Buffer']['Lockout']['LockoutThreshold']
                
                policy = {
                    'MinPasswordLength': min_pass_len,
                    'PasswordHistoryLength': pass_history,
                    'LockoutThreshold': lockout_thresh
                }
                policy_data[domain_name] = policy
                self.logger.info(f"Policy for {domain_name}: MinLength={min_pass_len}, History={pass_history}, Lockout={lockout_thresh}")

            dce.disconnect()
            return policy_data

        except Exception as e:
            self.logger.error(f"Error enumerating password policy: {e}")
            return None

    def enumerate_users(self):
        """Connect to SAMR via SMB transport and enumerate users."""
        self.logger.info("Attempting to enumerate users via SAMR over SMB...")
        users_list = []
        try:
            rpctransport = transport.SMBTransport(
                self.target,
                self.port,
                r'\samr',
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
            )
            dce = DCERPC_v5(rpctransport)
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']

            resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle=server_handle)
            domains = resp2['Buffer']['Buffer']
            
            for domain in domains:
                domain_name = domain['Name']
                
                resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle=server_handle, name=domain_name)
                # Ensure we have the right domain ID access
                resp4 = samr.hSamrOpenDomain(dce, serverHandle=server_handle, desiredAccess=samr.MAXIMUM_ALLOWED, domainId=resp3['DomainId'])
                domain_handle = resp4['DomainHandle']

                # Enumerate users
                status = samr.STATUS_MORE_ENTRIES
                enumerationContext = 0
                while status == samr.STATUS_MORE_ENTRIES:
                    try:
                        resp_users = samr.hSamrEnumerateUsersInDomain(dce, domainHandle=domain_handle, enumerationContext=enumerationContext)
                        status = resp_users['ErrorCode']
                        enumerationContext = resp_users['EnumerationContext']
                    except Exception as e:
                        if "STATUS_MORE_ENTRIES" in str(e):
                            resp_users = e.get_packet()
                            status = samr.STATUS_MORE_ENTRIES
                            enumerationContext = resp_users['EnumerationContext']
                        else:
                            raise e

                    for user in resp_users['Buffer']['Buffer']:
                        users_list.append({'domain': domain_name, 'username': user['Name'], 'rid': user['RelativeId']})
                        self.logger.info(f"Found User via SAMR: {domain_name}\\{user['Name']} (RID: {user['RelativeId']})")

                    if status != samr.STATUS_MORE_ENTRIES:
                        break

            dce.disconnect()
            return users_list

        except Exception as e:
            self.logger.error(f"Error enumerating users over SMB: {e}")
            return users_list

    def close(self):
        """Close the SMB connection."""
        if self.smb_conn:
            self.smb_conn.close()
            self.logger.info("SMB connection closed.")

if __name__ == '__main__':
    # Simple test execution example
    enum = SMBEnumerator('127.0.0.1', username='guest', password='')
    if enum.connect():
        enum.enumerate_shares()
        enum.get_password_policy()
        enum.close()
